"use components";

const emptyFunc = () => {};

let dv = new DataView(new ArrayBuffer());
const dataView = mem => dv.buffer === mem.buffer ? dv : dv = new DataView(mem.buffer);

function toInt64(val) {
  const converted = BigInt(val)
  
  return BigInt.asIntN(64, converted);
}


function toUint64(val) {
  const converted = BigInt(val)
  
  return BigInt.asUintN(64, converted);
}


function _isValidNumericPrimitive(ty, v) {
  if (v === undefined || v === null) { return false; }
  switch (ty) {
    case 'bool':
    return v === 0 || v === 1;
    break;
    case 'u8':
    return typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 255;
    break;
    case 's8':
    return typeof v === 'number' && Number.isInteger(v) && v >= -128 && v <= 127;
    break;
    case 'u16':
    return typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 65535;
    break;
    case 's16':
    return typeof v === 'number' && Number.isInteger(v) && v >= -32768 && v <= 32767;
    case 'u32':
    return typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 4_294_967_295;
    case 's32':
    return typeof v === 'number' && Number.isInteger(v) && v >= -2_147_483_648 && v <= 2_147_483_647;
    case 'u64':
    return typeof v === 'bigint' && v >= 0 && v <= 18_446_744_073_709_551_615n;
    case 's64':
    return typeof v === 'bigint' && v >= -9223372036854775808n && v <= 9223372036854775807n;
    break;
    case 'f32':
    case 'f64': return typeof v === 'number';
    default:
    return false;
  }
  return true;
}

function _requireValidNumericPrimitive(ty, v) {
  if (v === undefined  || v === null || !_isValidNumericPrimitive(ty, v)) {
    throw new TypeError(`invalid ${ty} value [${v}]`);
  }
  return true;
}
const TEXT_DECODER_UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const TEXT_ENCODER_UTF8 = new TextEncoder();

function _utf8AllocateAndEncode(s, realloc, memory) {
  if (typeof s !== 'string') {
    throw new TypeError('expected a string, received [' + typeof s + ']');
  }
  if (s.length === 0) { return { ptr: 1, len: 0 }; }
  // Compute the exact allocation size up front. Some older preview1
  // adapters only support an initial allocation, not a subsequent shrink.
  let len = 0;
  let codepoints = 0;
  for (let i = 0; i < s.length; i++) {
    const ch = s.charCodeAt(i);
    codepoints++;
    if (ch < 0x80) { len += 1; }
    else if (ch < 0x800) { len += 2; }
    else if (ch >= 0xd800 && ch <= 0xdbff &&
    i + 1 < s.length &&
    (s.charCodeAt(i + 1) & 0xfc00) === 0xdc00) {
      len += 4;
      i++;
    } else { len += 3; }
  }
  const ptr = realloc(0, 0, 1, len);
  const { read, written } = TEXT_ENCODER_UTF8.encodeInto(
  s,
  new Uint8Array(memory.buffer, ptr, len),
  );
  if (read !== s.length || written !== len) {
    throw new Error('failed to encode whole string');
  }
  const res = { ptr, len, codepoints };
  return res;
}

const T_FLAG = 1 << 30;
const HANDLE_INDEX_SPACES = new Map();

function getHandleIndexSpace(key) {
  let space = HANDLE_INDEX_SPACES.get(key);
  if (space === undefined) {
    // One index space per component instance (Canonical ABI
    // `inst.handles`): resource handles, waitables, waitable sets and
    // error contexts share it. Freed indices are reused LIFO, as
    // `Table.add` does. Index 0 is never a handle.
    space = {
      next: 1,
      free: [],
      alloc() { return this.free.length > 0 ? this.free.pop() : this.next++; },
      release(idx) { this.free.push(idx); },
    };
    HANDLE_INDEX_SPACES.set(key, space);
  }
  return space;
}


function rscTableCreateOwn(table, rep) {
  table._createdReps.add(rep);
  const handle = getHandleIndexSpace(table._componentIdx ?? table).alloc();
  table[handle << 1] = 0;
  table[(handle << 1) + 1] = rep | T_FLAG;
  return handle;
}

const RESOURCE_SCOPE_TASKS = new Map();
const WebAssemblyRuntimeError = WebAssembly.RuntimeError;

function rscTableRemove(table, handle) {
  const scope = table[handle << 1];
  const val = table[(handle << 1) + 1];
  const own = (val & T_FLAG) !== 0;
  const rep = val & ~T_FLAG;
  if (val === undefined || val === 0 || (scope & T_FLAG) !== 0) {
    throw new WebAssemblyRuntimeError(`unknown handle index ${handle}`);
  }
  if (own && scope !== 0) {
    throw new WebAssemblyRuntimeError('cannot remove owned resource while borrowed');
  }
  const borrowTask = own ? undefined : RESOURCE_SCOPE_TASKS.get(scope);
  // Mark the slot freed and give its index back to the instance's space.
  table[handle << 1] = T_FLAG;
  table[(handle << 1) + 1] = 0;
  getHandleIndexSpace(table._componentIdx ?? table).release(handle);
  borrowTask?.removeBorrowedHandle();
  return { rep, scope, own };
}

let RESOURCE_SCOPE_ID = 0;
const ASYNC_TASKS_BY_COMPONENT_IDX = new Map();
const ASYNC_CURRENT_TASK_IDS = [];
const ASYNC_CURRENT_COMPONENT_IDXS = [];

const _debugLog = (...args) => {
  if (!globalThis?.process?.env?.JCO_DEBUG) { return; }
  console.debug(...args);
};

function clearCurrentTask(componentIdx, taskID) {
  _debugLog('[clearCurrentTask()] args', { componentIdx, taskID });
  
  if (componentIdx === undefined || componentIdx === null) {
    throw new Error('missing/invalid component instance index while ending current task');
  }
  
  const tasks = ASYNC_TASKS_BY_COMPONENT_IDX.get(componentIdx);
  if (!tasks || !Array.isArray(tasks)) {
    throw new Error('missing/invalid tasks for component instance while ending task');
  }
  if (tasks.length == 0) {
    throw new Error(`no current tasks for component instance [${componentIdx}] while ending task`);
  }
  
  const taskIdx = taskID === undefined
  ? tasks.length - 1
  : tasks.findIndex(meta => meta.id === taskID);
  if (taskIdx === -1) { return; }
  
  const taskMeta = tasks.splice(taskIdx, 1)[0];
  const globalTaskIdx = ASYNC_CURRENT_TASK_IDS.lastIndexOf(taskMeta.id);
  if (globalTaskIdx !== -1) {
    ASYNC_CURRENT_TASK_IDS.splice(globalTaskIdx, 1);
    ASYNC_CURRENT_COMPONENT_IDXS.splice(globalTaskIdx, 1);
  }
  return taskMeta.task;
}
const ASYNC_STATE = new Map();

function promiseWithResolvers() {
  if (Promise.withResolvers) {
    return Promise.withResolvers();
  } else {
    let resolve;
    let reject;
    const promise = new Promise((res, rej) => {
      resolve = res;
      reject = rej;
    });
    return { promise, resolve, reject };
  }
}

class Waitable {
  #componentIdx;
  
  #pendingEventFn = null;
  
  #promise;
  #resolve;
  #reject;
  
  #waitableSet = null;
  
  #hasSyncWaiter = false;
  
  #idx = null; // to component-global waitables
  
  target;
  
  constructor(args) {
    const { componentIdx, target } = args;
    this.#componentIdx = componentIdx;
    this.target = args.target;
    this.#resetPromise();
  }
  
  componentIdx() { return this.#componentIdx; }
  isInSet() { return this.#waitableSet !== null; }
  
  idx() { return this.#idx; }
  setIdx(idx) {
    if (idx === 0) { throw new Error("waitable idx cannot be zero"); }
    this.#idx = idx;
  }
  
  setTarget(tgt) { this.target = tgt; }
  
  #resetPromise() {
    const { promise, resolve, reject } = promiseWithResolvers()
    this.#promise = promise;
    this.#resolve = resolve;
    this.#reject = reject;
  }
  
  resolve() { this.#resolve(); }
  reject(err) { this.#reject(err); }
  promise() { return this.#promise; }
  
  hasPendingEvent() {
    // _debugLog('[Waitable#hasPendingEvent()]', {
      //     componentIdx: this.#componentIdx,
      //     waitable: this,
      //     waitableSet: this.#waitableSet,
      //     hasPendingEvent: this.#pendingEventFn !== null,
      // });
      return this.#pendingEventFn !== null;
    }
    
    setPendingEvent(fn) {
      _debugLog('[Waitable#setPendingEvent()] args', {
        waitable: this,
        inSet: this.#waitableSet,
      });
      this.#pendingEventFn = fn;
    }
    
    getPendingEvent() {
      _debugLog('[Waitable#getPendingEvent()] args', {
        waitable: this,
        inSet: this.#waitableSet,
        hasPendingEvent: this.#pendingEventFn !== null,
      });
      if (this.#pendingEventFn === null) { return null; }
      const eventFn = this.#pendingEventFn;
      this.#pendingEventFn = null;
      const e = eventFn();
      this.#resetPromise();
      return e;
    }
    
    join(waitableSet) {
      _debugLog('[Waitable#join()] args', {
        waitable: this,
        waitableSet: waitableSet,
        isRemoval: waitableSet === null,
      });
      
      if (this.#waitableSet === undefined) {
        throw new TypeError('waitable set must be not be undefined');
      }
      
      if (this.#waitableSet) {
        this.#waitableSet.removeWaitable(this);
      }
      
      this.#waitableSet = waitableSet;
      
      if (waitableSet) {
        this.#waitableSet.addWaitable(this);
      }
    }
    
    drop() {
      _debugLog('[Waitable#drop()] args', {
        componentIdx: this.#componentIdx,
        waitable: this,
      });
      this.join(null);
    }
    
    async waitForPendingEvent(args) {
      const { cstate } = args;
      if (!cstate) { throw new TypeError('missing component state'); }
      
      if (this.#waitableSet !== null || this.#hasSyncWaiter) {
        throw new Error("waitable is already in a set/has a sync waiter");
      }
      this.#hasSyncWaiter = true;
      await cstate.waitUntil({
        cancellable: false,
        readyFn: () => this.hasPendingEvent(),
      });
      this.#hasSyncWaiter = false;
    }
    
  }
  const INSTANCE_FLAGS = new Map();
  const STORE_TRAP = { error: null };
  const STORE_ASYNC_STATE = { deadlockCheck: null, pendingHostOperations: 0 };
  
  function _checkForDeadlock() {
    if (STORE_ASYNC_STATE.deadlockCheck !== null || STORE_TRAP.error !== null) { return; }
    STORE_ASYNC_STATE.deadlockCheck = setTimeout(() => {
      STORE_ASYNC_STATE.deadlockCheck = null;
      if (STORE_TRAP.error !== null || STORE_ASYNC_STATE.pendingHostOperations > 0) { return; }
      
      const suspendedTasks = new Set();
      for (const state of ASYNC_STATE.values()) {
        if (state.hasPendingSchedulerWork()) {
          state.runTickLoop();
          return;
        }
        for (const meta of state.suspendedTaskMetas()) {
          suspendedTasks.add(meta.task);
        }
      }
      
      const unresolvedRoots = new Set();
      for (const task of suspendedTasks) {
        const root = task.getRootTask();
        if (!root.isResolvedState()) { unresolvedRoots.add(root); }
      }
      if (unresolvedRoots.size === 0) { return; }
      
      const err = new WebAssemblyRuntimeError('wasm trap: deadlock detected: event loop cannot make further progress');
      // Which tasks were waiting, and on whose behalf. The message stays
      // exactly what the Canonical ABI calls for, so this rides alongside
      // it: a deadlock reported from a real program is otherwise a bare
      // sentence, and the state that produced it is gone by the time
      // anyone reads the failure.
      err.deadlockDetail = {
        pendingHostOperations: STORE_ASYNC_STATE.pendingHostOperations,
        suspendedTasks: [...suspendedTasks].map((task) => ({
          taskID: task.id(),
          componentIdx: task.componentIdx(),
          state: task.taskState(),
          rootTaskID: task.getRootTask().id(),
        })),
        unresolvedRootTaskIDs: [...unresolvedRoots].map((root) => root.id()),
      };
      STORE_TRAP.error = err;
      for (const root of unresolvedRoots) {
        root.setErrored(err);
        root.reject(err);
      }
      for (const task of suspendedTasks) {
        if (!task.isResolvedState() && unresolvedRoots.has(task.getRootTask())) {
          task.setErrored(err);
          task.reject(err);
        }
      }
      // A deadlock is a trap of the whole store: no instance may be entered again.
      for (const state of ASYNC_STATE.values()) { state.markTrapped(err); }
      for (const state of ASYNC_STATE.values()) { state.abandonLockWaiters(); }
      for (const state of ASYNC_STATE.values()) { state.abandonAdmissionWaiters(); }
      for (const state of ASYNC_STATE.values()) { state.runTickLoop(); }
    }, 0);
  }
  
  const CORE_TRAP_MESSAGES = new Map([
  ['unreachable', "wasm trap: wasm `unreachable` instruction executed"],
  ['memory access out of bounds', "wasm trap: out of bounds memory access"],
  ['divide by zero', "wasm trap: integer divide by zero"],
  ['remainder by zero', "wasm trap: integer divide by zero"],
  ['divide result unrepresentable', "wasm trap: integer overflow"],
  ['float unrepresentable in integer range', "wasm trap: invalid conversion to integer"],
  ['table index is out of bounds', "wasm trap: undefined element: out of bounds table access"],
  ['function signature mismatch', "wasm trap: indirect call type mismatch"],
  ['call stack exhausted', "wasm trap: call stack exhausted"],
  ]);
  function _normalizeCoreTrap(err) {
    if (!(err instanceof WebAssemblyRuntimeError)) { return err; }
    const message = CORE_TRAP_MESSAGES.get(err.message);
    if (message !== undefined) { err.message = message; }
    return err;
  }
  
  class RepTable {
    // Sentinel marking a freed slot; the freelist link for a freed slot
    // lives in the odd cell. This keeps get()/contains()/remove() on freed
    // reps well-defined (previously they returned/corrupted freelist links).
    static FREE = Symbol('RepTable.free');
    
    #data = [0, null];
    #size = 0;
    #target;
    // An index space shared with the other handle kinds of a component
    // instance (see `getHandleIndexSpace`); without one, this table keeps
    // its own free list.
    #space = null;
    
    constructor(args) {
      this.target = args?.target;
      this.#space = args?.space ?? null;
    }
    
    data() { return this.#data; }
    
    insert(val) {
      if (this.#space !== null) {
        const rep = this.#space.alloc();
        this.#data[rep << 1] = val;
        this.#data[(rep << 1) + 1] = null;
        this.#size += 1;
        return rep;
      }
      _debugLog('[RepTable#insert()] args', { val, target: this.target });
      const freeIdx = this.#data[0];
      if (freeIdx === 0) {
        this.#data.push(val);
        this.#data.push(null);
        const rep = (this.#data.length >> 1) - 1;
        _debugLog('[RepTable#insert()] inserted', { val, target: this.target, rep });
        this.#size += 1;
        return rep;
      }
      const placementIdx = freeIdx << 1;
      if (this.#data[placementIdx] !== RepTable.FREE) {
        throw new Error('corrupt rep table freelist: head does not point at a freed slot');
      }
      this.#data[0] = this.#data[placementIdx + 1];
      this.#data[placementIdx] = val;
      this.#data[placementIdx + 1] = null;
      _debugLog('[RepTable#insert()] inserted', { val, target: this.target, rep: freeIdx });
      this.#size += 1;
      return freeIdx;
    }
    
    get(rep) {
      _debugLog('[RepTable#get()] args', { rep, target: this.target });
      if (rep === 0) { throw new WebAssemblyRuntimeError('invalid resource rep during get, (cannot be 0)'); }
      
      const baseIdx = rep << 1;
      const val = this.#data[baseIdx];
      if (val === RepTable.FREE) { return undefined; }
      return val;
    }
    
    contains(rep) {
      _debugLog('[RepTable#contains()] args', { rep, target: this.target });
      if (rep === 0) { throw new Error('invalid resource rep during contains, (cannot be 0)'); }
      
      const baseIdx = rep << 1;
      const val = this.#data[baseIdx];
      return val !== RepTable.FREE && !!val;
    }
    
    remove(rep) {
      _debugLog('[RepTable#remove()] args', { rep, target: this.target });
      if (rep === 0) { throw new Error('invalid resource rep during remove, (cannot be 0)'); }
      if (this.#space !== null) {
        const baseIdx = rep << 1;
        const val = this.#data[baseIdx];
        if (val === undefined || val === RepTable.FREE) {
          throw new WebAssemblyRuntimeError(`unknown handle index ${rep}`);
        }
        this.#data[baseIdx] = RepTable.FREE;
        this.#data[baseIdx + 1] = null;
        this.#size -= 1;
        this.#space.release(rep);
        return val;
      }
      if (this.#data.length === 2) { throw new Error('invalid'); }
      
      const baseIdx = rep << 1;
      if (baseIdx >= this.#data.length) {
        throw new Error(`invalid rep [${rep}] during remove, out of range`);
      }
      const val = this.#data[baseIdx];
      if (val === RepTable.FREE) {
        throw new WebAssemblyRuntimeError(`double removal of rep [${rep}] (already freed)`);
      }
      
      this.#data[baseIdx] = RepTable.FREE;
      this.#data[baseIdx + 1] = this.#data[0];
      this.#data[0] = rep;
      this.#size -= 1;
      
      return val;
    }
    
    size() { return this.#size; }
    
    clear() {
      _debugLog('[RepTable#clear()] args', { rep, target: this.target });
      this.#data = [0, null];
    }
  }
  
  class ComponentAsyncState {
    static EVENT_HANDLER_EVENTS = [ 'backpressure-change' ];
    
    static TickResult = {
      // no suspended tasks remain
      DONE: 'done',
      // a suspended task was resumed (more may be ready)
      RESUMED: 'resumed',
      // suspended tasks remain but none were ready
      IDLE: 'idle',
    };
    
    #componentIdx;
    #callingAsyncImport = false;
    #syncImportWait = promiseWithResolvers();
    #lockHolderTaskID = null;
    #lockWaiters = [];
    #admissionQueue = [];
    #lockHandoffScheduled = false;
    #pendingTaskStarts = 0;
    #parkedTasks = new Map();
    #suspendedTasksByTaskID = new Map();
    #suspendedTaskIDs = [];
    #errored = null;
    #trapped = false;
    #trapError = null;
    #backpressure = 0;
    #backpressureWaiters = 0n;
    
    #handlerMap = new Map();
    #nextHandlerID = 0n;
    
    #tickLoop = null;
    #tickLoopInterval = null;
    
    #onExclusiveReleaseHandlers = [];
    
    #mayLeave = true;
    
    handles;
    subtasks;
    
    constructor(args) {
      this.#componentIdx = args.componentIdx;
      this.handles = new RepTable({
        target: `component [${this.#componentIdx}] handles (waitable objects)`,
        space: getHandleIndexSpace(this.#componentIdx),
      });
      this.subtasks = new RepTable({ target: `component [${this.#componentIdx}] subtasks` });
    };
    
    componentIdx() { return this.#componentIdx; }
    
    get mayLeave() {
      const flags = INSTANCE_FLAGS.get(this.#componentIdx);
      return flags === undefined ? this.#mayLeave : flags.value === 1;
    }
    set mayLeave(value) {
      if (typeof value !== 'boolean') { throw new TypeError('mayLeave must be a boolean'); }
      this.#mayLeave = value;
      const flags = INSTANCE_FLAGS.get(this.#componentIdx);
      if (flags !== undefined) { flags.value = value ? 1 : 0; }
    }
    
    errored() { return this.#errored !== null; }
    setErrored(err) {
      _debugLog('[ComponentAsyncState#setErrored()] component errored', { err, componentIdx: this.#componentIdx });
      if (this.#errored) { return; }
      if (!err) {
        err = new Error('error elswehere (see other component instance error)')
        err.componentIdx = this.#componentIdx;
      }
      this.#errored = err;
    }
    
    markTrapped(err) {
      if (!(err instanceof WebAssemblyRuntimeError)) {
        return false;
      }
      err = _normalizeCoreTrap(err);
      this.#trapped = true;
      if (this.#trapError === null) { this.#trapError = err; }
      _debugLog('[ComponentAsyncState#markTrapped()] component trapped', { err, componentIdx: this.#componentIdx });
      if (STORE_TRAP.error === null) { STORE_TRAP.error = err; }
      return true;
    }
    
    isTrapped() { return this.#trapped; }
    // For work that was already under way or queued when the instance
    // trapped: it fails with that trap (nothing runs after a trap).
    throwIfInterrupted() {
      if (this.#trapped) {
        throw this.#trapError ?? new WebAssemblyRuntimeError("wasm trap: cannot enter component instance");
      }
    }
    throwIfTrapped() {
      if (this.#trapped) {
        throw new WebAssemblyRuntimeError("wasm trap: cannot enter component instance");
      }
    }
    
    callingSyncImport(val) {
      if (val === undefined) { return this.#callingAsyncImport; }
      if (typeof val !== 'boolean') { throw new TypeError('invalid setting for async import'); }
      const prev = this.#callingAsyncImport;
      this.#callingAsyncImport = val;
      if (prev === true && this.#callingAsyncImport === false) {
        this.#notifySyncImportEnd();
      }
    }
    
    #notifySyncImportEnd() {
      const existing = this.#syncImportWait;
      this.#syncImportWait = promiseWithResolvers();
      existing.resolve();
    }
    
    async waitForSyncImportCallEnd() {
      await this.#syncImportWait.promise;
    }
    
    setBackpressure(v) {
      this.#backpressure = v;
      return this.#backpressure
    }
    getBackpressure() { return this.#backpressure; }
    
    incrementBackpressure() {
      const current = this.#backpressure;
      if (current < 0 || current > 2**16) {
        throw new Error(`invalid current backpressure value [${current}]`);
      }
      const newValue = this.getBackpressure() + 1;
      if (newValue >= 2**16) {
        throw new Error(`invalid new backpressure value [${newValue}], overflow`);
      }
      return this.setBackpressure(newValue);
    }
    
    decrementBackpressure() {
      const current = this.#backpressure;
      if (current < 0 || current > 2**16) {
        throw new Error(`invalid current backpressure value [${current}]`);
      }
      // Canonical ABI `backpressure.dec`: trap if the counter would go
      // below zero.
      const newValue = current - 1;
      if (newValue < 0) {
        throw new WebAssemblyRuntimeError('backpressure counter underflow');
      }
      return this.setBackpressure(newValue);
    }
    hasBackpressure() { return this.#backpressure > 0; }
    
    waitForBackpressure() {
      let backpressureCleared = false;
      const cstate = this;
      cstate.addBackpressureWaiter();
      const handlerID = this.registerHandler({
        event: 'backpressure-change',
        fn: (bp) => {
          if (bp === 0) {
            cstate.removeHandler(handlerID);
            backpressureCleared = true;
          }
        }
      });
      return new Promise((resolve) => {
        const interval = setInterval(() => {
          if (backpressureCleared) { return; }
          clearInterval(interval);
          cstate.removeBackpressureWaiter();
          resolve(null);
        }, 0);
      });
    }
    
    registerHandler(args) {
      const { event, fn } = args;
      if (!event) { throw new Error("missing handler event"); }
      if (!fn) { throw new Error("missing handler fn"); }
      
      if (!ComponentAsyncState.EVENT_HANDLER_EVENTS.includes(event)) {
        throw new Error(`unrecognized event handler [${event}]`);
      }
      
      const handlerID = this.#nextHandlerID++;
      let handlers = this.#handlerMap.get(event);
      if (!handlers) {
        handlers = [];
        this.#handlerMap.set(event, handlers)
      }
      
      handlers.push({ id: handlerID, fn, event });
      return handlerID;
    }
    
    removeHandler(args) {
      const { event, handlerID } = args;
      const registeredHandlers = this.#handlerMap.get(event);
      if (!registeredHandlers) { return; }
      const found = registeredHandlers.find(h => h.id === handlerID);
      if (!found) { return; }
      this.#handlerMap.set(event, this.#handlerMap.get(event).filter(h => h.id !== handlerID));
    }
    
    getBackpressureWaiters() { return this.#backpressureWaiters; }
    addBackpressureWaiter() { this.#backpressureWaiters++; }
    removeBackpressureWaiter() {
      this.#backpressureWaiters--;
      if (this.#backpressureWaiters < 0) {
        throw new Error("unexepctedly negative number of backpressure waiters");
      }
    }
    
    // The per-slice mutual-exclusion lock for guest execution in this
    // component instance. Guest slices (callback invocations and
    // sync-lifted bodies) must be atomic per component even across the
    // JSPI suspensions jco introduces for host imports: wit-bindgen's
    // executors publish per-task state in single linear-memory cells
    // (the wasip3-task pointer, context-local storage discipline) that
    // an interleaved slice of the same component corrupts
    //
    // The lock is *owned*: acquisition records the holder task and
    // release is a no-op for anyone else, so a task exiting can no
    // longer drop a hold it does not own (blind acquire/release-any
    // was the previous discipline). Contended acquisition queues
    // FIFO; release hands the lock to the next waiter directly.
    isExclusivelyLocked() { return this.#lockHolderTaskID !== null; }
    exclusivelyLockedBy(taskID) { return this.#lockHolderTaskID === taskID; }
    
    exclusiveLock(taskID) {
      _debugLog('[ComponentAsyncState#exclusiveLock()]', {
        holder: this.#lockHolderTaskID,
        requester: taskID,
        componentIdx: this.#componentIdx,
      });
      if (taskID === undefined || taskID === null) {
        throw new Error('exclusive lock requires the acquiring task id');
      }
      if (this.#lockHolderTaskID !== null) {
        throw new Error(`component [${this.#componentIdx}] exclusive lock held by task [${this.#lockHolderTaskID}], requested by [${taskID}]`);
      }
      this.#lockHolderTaskID = taskID;
    }
    
    // Awaitable acquisition: takes the lock immediately when free,
    // otherwise queues FIFO behind the current holder and earlier
    // waiters. The resolved promise implies ownership.
    acquireExclusiveLock(taskID) {
      if (taskID === undefined || taskID === null) {
        throw new Error('exclusive lock requires the acquiring task id');
      }
      if (this.#lockHolderTaskID === null) {
        this.#lockHolderTaskID = taskID;
        _debugLog('[ComponentAsyncState#acquireExclusiveLock()] acquired', {
          holder: taskID,
          componentIdx: this.#componentIdx,
        });
        return;
      }
      if (this.#lockHolderTaskID === taskID) {
        throw new Error(`task [${taskID}] already holds the lock for component [${this.#componentIdx}]`);
      }
      _debugLog('[ComponentAsyncState#acquireExclusiveLock()] waiting', {
        holder: this.#lockHolderTaskID,
        requester: taskID,
        componentIdx: this.#componentIdx,
        queued: this.#lockWaiters.length,
      });
      return new Promise((resolve) => {
        this.#lockWaiters.push({ taskID, resolve });
      });
    }
    
    // Release every queued entry without granting ownership, so that
    // calls waiting to enter a trapped store fail instead of hanging.
    // FIFO admission of tasks entering this instance (Canonical ABI
    // `inst.pending`): a task enters only after every task that asked to
    // enter before it has entered or given up, so calls enter in the order
    // they were made, whatever each waits for on the way.
    takeAdmissionTicket(taskID) {
      const ticket = { taskID, ...promiseWithResolvers() };
      this.#admissionQueue.push(ticket);
      return ticket;
    }
    hasPendingAdmissions() { return this.#admissionQueue.length > 0; }
    waitForAdmissionTurn(ticket) {
      if (this.#admissionQueue[0] === ticket) { return; }
      return ticket.promise;
    }
    releaseAdmissionTicket(ticket) {
      const idx = this.#admissionQueue.indexOf(ticket);
      if (idx === -1) { return; }
      this.#admissionQueue.splice(idx, 1);
      if (idx === 0 && this.#admissionQueue.length > 0) {
        this.#admissionQueue[0].resolve();
      }
    }
    // Release every queued entry (the instance trapped): each then fails
    // in `enter()` instead of waiting forever.
    abandonAdmissionWaiters() {
      const tickets = this.#admissionQueue.splice(0);
      for (const ticket of tickets) { ticket.resolve(); }
    }
    
    abandonLockWaiters() {
      const waiters = this.#lockWaiters.splice(0);
      for (const waiter of waiters) { waiter.resolve(); }
    }
    
    cancelExclusiveLockWaiter(taskID) {
      const idx = this.#lockWaiters.findIndex(waiter => waiter.taskID === taskID);
      if (idx === -1) { return false; }
      const [waiter] = this.#lockWaiters.splice(idx, 1);
      // Release the awaiting `enter()` continuation without granting
      // ownership. It observes the task's resolved cancellation state
      // before attempting to execute guest code.
      waiter.resolve();
      return true;
    }
    
    exclusiveRelease(taskID) {
      _debugLog('[ComponentAsyncState#exclusiveRelease()] args', {
        holder: this.#lockHolderTaskID,
        releaser: taskID,
        componentIdx: this.#componentIdx,
      });
      if (this.#lockHolderTaskID !== taskID) {
        // Ownerless releases were the historical behavior; a foreign
        // release now leaves the hold intact
        _debugLog('[ComponentAsyncState#exclusiveRelease()] ignoring foreign release', {
          holder: this.#lockHolderTaskID,
          releaser: taskID,
          componentIdx: this.#componentIdx,
        });
        return false;
      }
      
      // Make the release observable before handing the lock to the next
      // asynchronous guest slice.
      //
      // Release handlers may expose a lifted value whose consumer immediately
      // performs a synchronous call on the same component; that call must run
      // while the instance is genuinely unlocked, not via enterSync's
      // lock-free fallback code.
      this.#lockHolderTaskID = null;
      
      this.#onExclusiveReleaseHandlers = this.#onExclusiveReleaseHandlers.filter(v => !!v);
      for (const [idx, f] of this.#onExclusiveReleaseHandlers.entries()) {
        try {
          this.#onExclusiveReleaseHandlers[idx] = null;
          f();
        } catch (err) {
          _debugLog("error while executing handler for next exclusive release", err);
          throw err;
        }
      }
      this.#scheduleLockHandoff();
      return true;
    }
    
    #scheduleLockHandoff() {
      if (this.#lockHandoffScheduled || this.#lockWaiters.length === 0) { return; }
      this.#lockHandoffScheduled = true;
      queueMicrotask(() => {
        this.#lockHandoffScheduled = false;
        // A synchronous call triggered by a release handler gets the
        // first opportunity to use the unlocked component. Its own
        // release schedules the next handoff; re-queueing one here
        // would spin the microtask queue for as long as the holder
        // stays blocked (e.g. in a synchronous wait), starving every
        // timer, the deadlock detector included.
        if (this.#lockHolderTaskID !== null) { return; }
        const next = this.#lockWaiters.shift();
        if (!next) { return; }
        this.#lockHolderTaskID = next.taskID;
        next.resolve();
      });
    }
    
    onNextExclusiveRelease(fn) {
      _debugLog('[ComponentAsyncState#()onNextExclusiveRelease] registering');
      this.#onExclusiveReleaseHandlers.push(fn);
    }
    
    async waitForExclusiveRelease() {
      while (this.isExclusivelyLocked()) {
        await new Promise(resolve => this.onNextExclusiveRelease(resolve));
      }
    }
    
    #getSuspendedTaskMeta(taskID) {
      return this.#suspendedTasksByTaskID.get(taskID);
    }
    
    #removeSuspendedTaskMeta(taskID) {
      _debugLog('[ComponentAsyncState#removeSuspendedTaskMeta()] removing suspended task', {
        taskID,
        componentIdx: this.#componentIdx,
      });
      const idx = this.#suspendedTaskIDs.findIndex(t => t === taskID);
      const meta = this.#suspendedTasksByTaskID.get(taskID);
      this.#suspendedTaskIDs[idx] = null;
      this.#suspendedTasksByTaskID.delete(taskID);
      return meta;
    }
    
    #addSuspendedTaskMeta(meta) {
      if (!meta) { throw new Error('missing task meta'); }
      const taskID = meta.taskID;
      this.#suspendedTasksByTaskID.set(taskID, meta);
      this.#suspendedTaskIDs.push(taskID);
      if (this.#suspendedTasksByTaskID.size < this.#suspendedTaskIDs.length - 10) {
        this.#suspendedTaskIDs = this.#suspendedTaskIDs.filter(t => t !== null);
      }
    }
    
    // TODO(threads): readyFn is normally on the thread
    suspendTask(args) {
      const { task, readyFn, cancellable, onResume } = args;
      const taskID = task.id();
      const componentIdx = task.componentIdx();
      // (a blocked task ended its first slice)
      task.endFirstSlice();
      _debugLog('[ComponentAsyncState#suspendTask()]', {
        taskID,
        componentIdx: this.#componentIdx,
        taskEntryFnName: task.entryFnName(),
        subtask: task.getParentSubtask(),
      });
      
      if (componentIdx !== this.#componentIdx) {
        throw new Error('assert: task component idx should match async state');
      }
      
      if (this.#getSuspendedTaskMeta(taskID)) {
        throw new Error(`task [${taskID}] already suspended`);
      }
      
      let promise;
      let resume;
      if (onResume) {
        resume = () => onResume(!task.isCancelled());
      } else {
        const resolvers = promiseWithResolvers();
        promise = resolvers.promise;
        resume = () => resolvers.resolve(!task.isCancelled());
      }
      this.#addSuspendedTaskMeta({
        task,
        taskID,
        cancellable,
        readyFn,
        resume: () => {
          _debugLog('[ComponentAsyncState] resuming suspended task', {
            taskID,
            componentIdx: this.#componentIdx,
          });
          // TODO(threads): it's thread cancellation we should be checking for below, not task
          resume();
        },
      });
      
      // A caller synchronously driving one task quantum (for
      // example, subtask.cancel) waits for the resumed task to
      // either resolve or suspend again.
      task.notifyProgress();
      
      this.runTickLoop();
      _checkForDeadlock();
      
      return promise;
    }
    
    resumeTaskByID(taskID) {
      const meta = this.#removeSuspendedTaskMeta(taskID);
      if (!meta) { return false; }
      if (meta.taskID !== taskID) { throw new Error('task ID does not match'); }
      meta.resume();
      return true;
    }
    
    suspendedTaskReady(taskID) {
      const meta = this.#getSuspendedTaskMeta(taskID);
      if (!meta) { return false; }
      if (!meta.readyFn) {
        throw new Error(`suspended task [${taskID}] is missing a readiness function`);
      }
      if (meta.task.isRejected()) { return true; }
      if (!meta.readyFn()) { return false; }
      return !meta.task.needsExclusiveLock()
      || !this.isExclusivelyLocked()
      || this.exclusivelyLockedBy(taskID);
    }
    
    suspendedTaskCancellable(taskID) {
      return !!this.#getSuspendedTaskMeta(taskID)?.cancellable;
    }
    
    isTaskSuspended(taskID) {
      return this.#suspendedTasksByTaskID.has(taskID);
    }
    
    suspendedTaskMetas() {
      return this.#suspendedTasksByTaskID.values();
    }
    
    addPendingTaskStart() { this.#pendingTaskStarts++; }
    removePendingTaskStart() { this.#pendingTaskStarts--; }
    
    hasPendingSchedulerWork() {
      if (this.#pendingTaskStarts > 0) { return true; }
      if (this.#lockHandoffScheduled) { return true; }
      for (const meta of this.#suspendedTasksByTaskID.values()) {
        if (meta.task.isRejected() || meta.readyFn()) { return true; }
      }
      return false;
    }
    
    async runTickLoop() {
      if (this.#tickLoop !== null) { return; }
      this.#tickLoop = 1;
      setTimeout(async () => {
        let result = this.tick();
        while (result !== ComponentAsyncState.TickResult.DONE) {
          if (result === ComponentAsyncState.TickResult.IDLE) {
            _checkForDeadlock();
          }
          // After resuming a task, re-tick as soon as the resumed
          // slice's microtask continuations have drained (timeout 0)
          // so queued sibling resumptions aren't charged the idle
          // polling interval; otherwise poll at the idle cadence.
          const delay = result === ComponentAsyncState.TickResult.RESUMED ? 0 : 10;
          await new Promise((resolve) => setTimeout(resolve, delay));
          result = this.tick();
        }
        this.#tickLoop = null;
      }, 10);
    }
    
    tick() {
      // _debugLog('[ComponentAsyncState#tick()]', { suspendedTaskIDs: this.#suspendedTaskIDs });
      
      const resumableTasks = this.#suspendedTaskIDs.filter(t => t !== null);
      for (const taskID of resumableTasks) {
        const meta = this.#suspendedTasksByTaskID.get(taskID);
        if (!meta || !meta.readyFn) {
          throw new Error(`missing/invalid task despite ID [${taskID}] being present`);
        }
        
        // If the task failed via any means, allow the task to resume because
        // it's been cancelled -- the callback should immediately exit as well
        if (meta.task.isRejected()) {
          _debugLog('[ComponentAsyncState#tick()] detected task rejection, leaving early', { meta });
          this.resumeTaskByID(taskID);
          return ComponentAsyncState.TickResult.RESUMED;
        }
        
        const isReady = this.suspendedTaskReady(taskID);
        if (!isReady) { continue; }
        
        _debugLog('[ComponentAsyncState#tick()] resuming task via tick', {
          taskID,
          componentIdx: this.#componentIdx,
        });
        this.resumeTaskByID(taskID);
        
        // NOTE: during single-flight resumption, we should resume at most one task per
        // tick so that the resumed slice (a microtask continuation)
        // runs -- and its current-task register window opens and
        // closes -- before any sibling task of this component is
        // resumed.
        //
        // Resuming multiple suspended tasks in one synchronous
        // cascade interleaves their register save/restore windows
        // ([restoreA, restoreB, resumeA, resumeB]), re-entering wasm
        // with the register naming the wrong task, and the
        // 'known residual' of the JSPI current-task register
        // fix); with concurrent task lifetimes per component this
        // corrupts guest context-local storage.
        return ComponentAsyncState.TickResult.RESUMED;
      }
      
      const idle = this.#suspendedTaskIDs.filter(t => t !== null).length > 0;
      return idle
      ? ComponentAsyncState.TickResult.IDLE
      : ComponentAsyncState.TickResult.DONE;
    }
    
    createWaitable(args) {
      return new Waitable({ target: args?.target, });
    }
  }
  
  function getOrCreateAsyncState(componentIdx, init) {
    if (!ASYNC_STATE.has(componentIdx)) {
      const newState = new ComponentAsyncState({ componentIdx });
      ASYNC_STATE.set(componentIdx, newState);
    }
    return ASYNC_STATE.get(componentIdx);
  }
  const symbolDispose = Symbol.dispose || Symbol.for('dispose');
  
  // Dispose of a host-provided value that a guest discarded, using `disposeFn`
  // if provided, otherwise the value's `Symbol.asyncDispose` or `Symbol.dispose`.
  //
  // Disposal runs in a microtask, so host code never runs inside a canonical
  // built-in (where it could re-enter the component), and errors are reported
  // rather than surfaced to the guest.
  function _disposeHostValue(value, disposeFn) {
    if (!disposeFn) {
      if (value === null || (typeof value !== 'object' && typeof value !== 'function')) { return; }
      if (typeof Symbol.asyncDispose === 'symbol' && typeof value[Symbol.asyncDispose] === 'function') {
        disposeFn = value[Symbol.asyncDispose];
      } else if (typeof value[symbolDispose] === 'function') {
        disposeFn = value[symbolDispose];
      } else {
        return;
      }
    }
    const reportErr = (err) => console.error('[jco] error while disposing discarded host value', err);
    queueMicrotask(() => {
      try {
        const res = disposeFn.call(value);
        if (res && typeof res.then === 'function') { res.then(undefined, reportErr); }
      } catch (err) {
        reportErr(err);
      }
    });
  }
  
  const GLOBAL_COMPONENT_MEMORY_MAP = new Map();
  
  function lookupMemoriesForComponent(args) {
    const { componentIdx } = args ?? {};
    if (args.componentIdx === undefined) { throw new TypeError("missing component idx"); }
    
    const metas = GLOBAL_COMPONENT_MEMORY_MAP.get(componentIdx);
    if (!metas) { return []; }
    
    if (args.memoryIdx === undefined) {
      return Object.values(metas);
    }
    
    const meta = metas[args.memoryIdx];
    return meta?.memory;
  }
  
  class AsyncSubtask {
    static _ID = 0n;
    
    static State = {
      STARTING: 0,
      STARTED: 1,
      RETURNED: 2,
      CANCELLED_BEFORE_STARTED: 3,
      CANCELLED_BEFORE_RETURNED: 4,
    };
    
    #id;
    #state = AsyncSubtask.State.STARTING;
    #componentIdx;
    
    #parentTask;
    #childTask = null;
    
    #dropped = false;
    #cancelRequested = false;
    
    #memoryIdx = null;
    #lenders = null;
    
    #waitable = null;
    
    #callbackFn = null;
    #callbackFnName = null;
    
    #postReturnFn = null;
    #onProgressFn = null;
    #pendingEventFn = null;
    
    #callMetadata = {};
    
    #resolved = false;
    
    #onResolveHandlers = [];
    #onStartHandlers = [];
    
    #result = null;
    #resultSet = false;
    
    // Pending value returned by a host implementation of this (async import)
    // subtask, held so it can be disposed if the guest discards the call
    #hostPendingResult = null;
    
    fnName;
    target;
    isAsync;
    isManualAsync;
    // One execution slice awaited by the conditional cancel trampoline.
    cancelProgress = null;
    
    constructor(args) {
      if (typeof args.componentIdx !== 'number') {
        throw new Error('invalid componentIdx for subtask creation');
      }
      this.#componentIdx = args.componentIdx;
      
      this.#id = ++AsyncSubtask._ID;
      this.fnName = args.fnName;
      
      if (!args.parentTask) { throw new Error('missing parent task during subtask creation'); }
      this.#parentTask = args.parentTask;
      
      if (args.childTask) { this.#childTask = args.childTask; }
      
      if (args.memoryIdx) { this.#memoryIdx = args.memoryIdx; }
      
      if (!args.waitable) { throw new Error("missing/invalid waitable"); }
      this.#waitable = args.waitable;
      
      if (args.callMetadata) { this.#callMetadata = args.callMetadata; }
      
      this.#lenders = [];
      this.target = args.target;
      this.isAsync = args.isAsync;
      this.isManualAsync = args.isManualAsync;
    }
    
    id() { return this.#id; }
    parentTaskID() { return this.#parentTask?.id(); }
    childTaskID() { return this.#childTask?.id(); }
    state() { return this.#state; }
    
    waitable() { return this.#waitable; }
    waitableRep() { return this.#waitable.idx(); }
    // The handle index is allocated only when the guest gets to see the
    // subtask (an async lower that did not complete at once), and after the
    // lifted arguments have freed theirs (Canonical ABI `canon_lower`).
    ensureHandle() {
      const existing = this.#waitable.idx();
      if (existing !== null && existing !== undefined) { return existing; }
      const idx = this.#getComponentState().handles.insert(this);
      this.#waitable.setIdx(idx);
      this.#waitable.setTarget(`waitable for subtask (waitable id [${idx}], subtask internal ID [${this.id()}])`);
      return idx;
    }
    
    join() { return this.#waitable.join(...arguments); }
    getPendingEvent() { return this.#waitable.getPendingEvent(...arguments); }
    hasPendingEvent() { return this.#waitable.hasPendingEvent(...arguments); }
    setPendingEvent() { return this.#waitable.setPendingEvent(...arguments); }
    
    setTarget(tgt) { this.target = tgt; }
    
    getResult() {
      if (!this.#resultSet) { throw new Error("subtask result has not been set") }
      return this.#result;
    }
    setResult(v) {
      if (this.#resultSet) { throw new Error("subtask result has already been set"); }
      this.#result = v;
      this.#resultSet = true;
    }
    
    componentIdx() { return this.#componentIdx; }
    
    setChildTask(t) {
      if (!t) { throw new Error('cannot set missing/invalid child task on subtask'); }
      if (this.#childTask) { throw new Error('child task is already set on subtask'); }
      if (this.#parentTask === t) { throw new Error("parent cannot be child"); }
      this.#childTask = t;
    }
    getChildTask(t) { return this.#childTask; }
    
    getParentTask() { return this.#parentTask; }
    
    setCallbackFn(f, name) {
      if (!f) { return; }
      if (this.#callbackFn) { throw new Error('callback fn can only be set once'); }
      this.#callbackFn = f;
      this.#callbackFnName = name;
    }
    
    getCallbackFnName() {
      if (!this.#callbackFn) { return undefined; }
      return this.#callbackFn.name;
    }
    
    setPostReturnFn(f) {
      if (!f) { return; }
      if (this.#postReturnFn) { throw new Error('postReturn fn can only be set once'); }
      this.#postReturnFn = f;
    }
    
    setOnProgressFn(f) {
      if (this.#onProgressFn) { throw new Error('on progress fn can only be set once'); }
      this.#onProgressFn = f;
    }
    
    isNotStarted() {
      return this.#state == AsyncSubtask.State.STARTING;
    }
    
    cancellationRequested() { return this.#cancelRequested; }
    
    // Request cooperative cancellation of this subtask, on behalf of the
    // supertask (i.e. `canon subtask.cancel`).
    //
    // If the callee is another guest task, the request is delivered to it and
    // the callee confirms via `task.cancel` (or still resolves via `task.return`).
    //
    // If the callee is a host function, the pending call is treated as
    // immediately cancelled -- consistent with hosts being expected to resolve
    // cancellation promptly -- and any later host resolution is discarded
    // (see `AsyncTask#onResolve`). The host is notified of the discard by
    // disposing the pending value it returned (see `setHostPendingResult`).
    requestCancellation() {
      _debugLog('[AsyncSubtask#requestCancellation()] args', {
        componentIdx: this.#componentIdx,
        subtaskID: this.#id,
        state: this.#state,
        childTaskID: this.childTaskID(),
        fnName: this.fnName,
      });
      if (this.#cancelRequested) {
        throw new Error('cancellation has already been requested for this subtask');
      }
      this.#cancelRequested = true;
      
      if (this.#resolved) { return; }
      
      if (this.#childTask) {
        this.#childTask.requestCancellation();
        return;
      }
      
      this.onResolve(null);
      this.#disposeHostPendingResult();
    }
    
    // Record the value returned by the host implementation of this subtask.
    //
    // Host imports may return a thenable that implements `Symbol.asyncDispose`
    // or `Symbol.dispose`. If the guest cancels the call before its result is
    // delivered, the result is discarded and the thenable is disposed so the
    // host can stop pending work and release anything it produced.
    setHostPendingResult(v) {
      if (v === null || (typeof v !== 'object' && typeof v !== 'function') || typeof v.then !== 'function') {
        return;
      }
      this.#hostPendingResult = v;
      if (this.#resolved && this.#state !== AsyncSubtask.State.RETURNED) {
        this.#disposeHostPendingResult();
      }
    }
    
    #disposeHostPendingResult() {
      const pending = this.#hostPendingResult;
      if (!pending) { return; }
      this.#hostPendingResult = null;
      _disposeHostValue(pending);
    }
    
    registerOnStartHandler(f) {
      this.#onStartHandlers.push(f);
    }
    
    onStart(args) {
      _debugLog('[AsyncSubtask#onStart()] args', {
        componentIdx: this.#componentIdx,
        subtaskID: this.#id,
        parentTaskID: this.parentTaskID(),
        fnName: this.fnName,
        args,
      });
      
      if (this.#onProgressFn) { this.#onProgressFn(); }
      
      // Starting a nested operation is a task execution boundary.
      // In particular, a cancellation handler may synchronously
      // enter an import which then suspends in the host.  Wake a
      // supertask that is driving one cancellation slice so an
      // async `subtask.cancel` can report BLOCKED without waiting
      // for that nested operation to finish.
      this.#parentTask.notifyProgress();
      
      this.#state = AsyncSubtask.State.STARTED;
      
      let result;
      
      // If we have been provided a helper start function as a result of
      // component fusion performed by wasmtime tooling, then we can call that helper and lifts/lowers will
      // be performed for us.
      //
      // See also documentation on `HostIntrinsic::PrepareCall`
      //
      if (this.#callMetadata.startFn) {
        result = this.#callMetadata.startFn.apply(null, args?.startFnParams ?? []);
      }
      
      return result;
    }
    
    
    registerOnResolveHandler(f) {
      this.#onResolveHandlers.push(f);
    }
    
    reject(subtaskErr) {
      if (this.#resolved) { return; }
      
      if (this.#onProgressFn) { this.#onProgressFn(); }
      
      if (this.#state === AsyncSubtask.State.STARTING) {
        this.#state = AsyncSubtask.State.CANCELLED_BEFORE_STARTED;
      } else if (this.#state === AsyncSubtask.State.STARTED) {
        this.#state = AsyncSubtask.State.CANCELLED_BEFORE_RETURNED;
      } else {
        throw new Error('cannot reject a completed subtask');
      }
      
      this.#resolved = true;
      this.#hostPendingResult = null;
      this.#parentTask.removeSubtask(this);
      this.#parentTask.reject(subtaskErr);
    }
    
    onResolve(subtaskValue) {
      _debugLog('[AsyncSubtask#onResolve()] args', {
        componentIdx: this.#componentIdx,
        subtaskID: this.#id,
        isAsync: this.isAsync,
        childTaskID: this.childTaskID(),
        parentTaskID: this.parentTaskID(),
        parentTaskFnName: this.#parentTask?.entryFnName(),
        fnName: this.fnName,
      });
      
      if (this.#resolved) {
        throw new Error('subtask has already been resolved');
      }
      
      if (this.#onProgressFn) { this.#onProgressFn(); }
      
      if (subtaskValue === null && this.#cancelRequested) {
        if (this.#state === AsyncSubtask.State.STARTING) {
          this.#state = AsyncSubtask.State.CANCELLED_BEFORE_STARTED;
        } else {
          if (this.#state !== AsyncSubtask.State.STARTED) {
            throw new Error('resolved subtask must have been started before cancellation');
          }
          this.#state = AsyncSubtask.State.CANCELLED_BEFORE_RETURNED;
        }
      } else {
        if (this.#state !== AsyncSubtask.State.STARTED) {
          throw new Error('resolved subtask must have been started before completion');
        }
        this.#state = AsyncSubtask.State.RETURNED;
        // The host result is delivered to the guest, so it is no longer ours to dispose
        this.#hostPendingResult = null;
      }
      
      this.setResult(subtaskValue);
      
      for (const f of this.#onResolveHandlers) {
        try {
          f(subtaskValue);
        } catch (err) {
          console.error("error during subtask resolve handler", err);
          throw err;
        }
      }
      
      const callMetadata = this.getCallMetadata();
      
      // TODO(fix): we should be able to easily have the caller's meomry
      // to lower into here, but it's not present in PrepareCall
      const memory = callMetadata.memory ?? this.#parentTask?.getReturnMemory() ?? lookupMemoriesForComponent({ componentIdx: this.#parentTask?.componentIdx() })[0];
      // NOTE: cancelled resolutions carry no value, so nothing is lowered
      const returned = this.#state === AsyncSubtask.State.RETURNED;
      if (returned && callMetadata && !callMetadata.returnFn && (this.isAsync || callMetadata.funcTypeIsAsync) && callMetadata.resultPtr && memory) {
        const { resultPtr, realloc } = callMetadata;
        const lowers = callMetadata.lowers; // may have been updated in task.return of the child
        if (lowers && lowers.length > 0) {
          lowers[0]({
            componentIdx: this.#componentIdx,
            memory,
            realloc,
            vals: [subtaskValue],
            storagePtr: resultPtr,
            stringEncoding: callMetadata.stringEncoding,
          });
        }
      }
      
      this.#resolved = true;
      this.#parentTask.removeSubtask(this);
      
      if (!this.isAsync) {
        this.deliverResolve();
        const rep = this.waitableRep();
        if (rep) {
          try {
            const removed = this.#getComponentState().handles.remove(rep);
            if (removed !== this) {
              throw new Error("unexpectedly received non-self Subtask from handle removal");
            }
            this.drop();
          } catch (err) {
            _debugLog('[AsyncSubtask#onResolve()] failed to remove subtask after sync subtask completion', err);
          }
        }
      }
    }
    
    getStateNumber() { return this.#state; }
    isReturned() { return this.#state === AsyncSubtask.State.RETURNED; }
    
    getCallMetadata() { return this.#callMetadata; }
    
    isResolved() {
      if (this.#state === AsyncSubtask.State.STARTING
      || this.#state === AsyncSubtask.State.STARTED) {
        return false;
      }
      if (this.#state === AsyncSubtask.State.RETURNED
      || this.#state === AsyncSubtask.State.CANCELLED_BEFORE_STARTED
      || this.#state === AsyncSubtask.State.CANCELLED_BEFORE_RETURNED) {
        return true;
      }
      throw new Error('unrecognized internal Subtask state [' + this.#state + ']');
    }
    
    addLender(handle) {
      _debugLog('[AsyncSubtask#addLender()] args', { handle });
      if (!Number.isNumber(handle)) { throw new Error('missing/invalid lender handle [' + handle + ']'); }
      
      if (this.#lenders.length === 0 || this.isResolved()) {
        throw new Error('subtask has no lendors or has already been resolved');
      }
      
      handle.lends++;
      this.#lenders.push(handle);
    }
    
    deliverResolve() {
      _debugLog('[AsyncSubtask#deliverResolve()] args', {
        lenders: this.#lenders,
        parentTaskID: this.parentTaskID(),
        subtaskID: this.#id,
        childTaskID: this.childTaskID(),
        resolved: this.isResolved(),
        resolveDelivered: this.resolveDelivered(),
      });
      
      const cannotDeliverResolve = this.resolveDelivered() || !this.isResolved();
      if (cannotDeliverResolve) {
        throw new Error('subtask cannot deliver resolution twice, and the subtask must be resolved');
      }
      
      for (const lender of this.#lenders) {
        lender.lends--;
      }
      
      this.#lenders = null;
    }
    
    resolveDelivered() {
      _debugLog('[AsyncSubtask#resolveDelivered()] args', { });
      if (this.#lenders === null && !this.isResolved()) {
        throw new Error('invalid subtask state, lenders missing and subtask has not been resolved');
      }
      return this.#lenders === null;
    }
    
    drop() {
      _debugLog('[AsyncSubtask#drop()] args', {
        componentIdx: this.#componentIdx,
        parentTaskID: this.#parentTask?.id(),
        parentTaskFnName: this.#parentTask?.entryFnName(),
        childTaskID: this.#childTask?.id(),
        childTaskFnName: this.#childTask?.entryFnName(),
        subtaskFnName: this.fnName,
      });
      if (!this.#waitable) { throw new Error('missing/invalid inner waitable'); }
      if (!this.resolveDelivered()) {
        throw new Error('cannot drop a subtask which has not yet resolved');
      }
      if (this.#waitable) { this.#waitable.drop() }
      this.#dropped = true;
    }
    
    #getComponentState() {
      const state = getOrCreateAsyncState(this.#componentIdx);
      if (!state) {
        throw new Error('invalid/missing async state for component [' + componentIdx + ']');
      }
      return state;
    }
    
    getWaitableHandleIdx() {
      _debugLog('[AsyncSubtask#getWaitableHandleIdx()] args', { });
      if (!this.#waitable) { throw new Error('missing/invalid waitable'); }
      return this.waitableRep();
    }
  }
  
  class FutureValue {
    #start;
    #settled;
    #hideThen = 0;
    #thenFn;
    
    constructor(start) {
      if (typeof start !== 'function') {
        throw new TypeError('future start operation must be a function');
      }
      this.#start = start;
      this.#thenFn = this.#then.bind(this);
    }
    
    get then() {
      return this.#hideThen === 0 ? this.#thenFn : undefined;
    }
    
    #read() {
      if (!this.#settled) {
        // The start operation resolves to a non-thenable box so a
        // future-valued payload cannot be assimilated by this Promise.
        this.#settled = Promise.resolve().then(this.#start);
      }
      return this.#settled;
    }
    
    resolveAsValue(resolve) {
      this.#hideThen++;
      try {
        resolve(this);
      } finally {
        this.#hideThen--;
      }
    }
    
    #deliver(resolve, value) {
      if (value instanceof FutureValue) {
        // Promise resolution reads `then` synchronously. Hide it only
        // for that lookup so resolving this layer yields the inner
        // FutureValue instead of recursively awaiting it.
        value.resolveAsValue(resolve);
        return;
      }
      resolve(value);
    }
    
    #then(resolve, reject) {
      return this.#read().then(
      box => this.#deliver(resolve, box.value),
      reject,
      );
    }
  }
  const ASYNC_DETERMINISM = 'random';
  const _coinFlip = () => { return Math.random() > 0.5; };
  
  const ASYNC_EVENT_CODE = {
    NONE: 0,
    SUBTASK: 1,
    STREAM_READ: 2,
    STREAM_WRITE: 3,
    FUTURE_READ: 4,
    FUTURE_WRITE: 5,
    TASK_CANCELLED: 6,
  };
  const CURRENT_TASK_META = {};
  
  function _withGlobalCurrentTaskMeta(args) {
    _debugLog('[_withGlobalCurrentTaskMeta()] args', args);
    if (!args) { throw new TypeError('args missing'); }
    if (args.taskID === undefined) { throw new TypeError('missing task ID'); }
    if (args.componentIdx === undefined) { throw new TypeError('missing component idx'); }
    if (!args.fn) { throw new TypeError('missing fn'); }
    const { taskID, componentIdx, fn } = args;
    const previous = CURRENT_TASK_META[componentIdx] ?? null;
    const previousCurrent = CURRENT_TASK_META.current ?? null;
    
    try {
      CURRENT_TASK_META.current =
      CURRENT_TASK_META[componentIdx] = { taskID, componentIdx };
      return fn();
    } catch (err) {
      _debugLog("error while executing sync callee/callback", {
        ...args,
        err,
      });
      throw err;
    } finally {
      // Synchronous wrappers can nest without any intervening JS
      // scheduling. Restore the caller rather than clearing it so
      // helper core exports (for example fused return adapters) can
      // temporarily run under a different task of the same component.
      CURRENT_TASK_META[componentIdx] = previous;
      CURRENT_TASK_META.current = previousCurrent;
    }
  }
  
  async function _withGlobalCurrentTaskMetaAsync(args) {
    _debugLog('[_withGlobalCurrentTaskMetaAsync()] args', args);
    if (!args) { throw new TypeError('args missing'); }
    if (args.taskID === undefined) { throw new TypeError('missing task ID'); }
    if (args.componentIdx === undefined) { throw new TypeError('missing component idx'); }
    if (!args.fn) { throw new TypeError('missing fn'); }
    
    const { taskID, componentIdx, fn } = args;
    
    try {
      CURRENT_TASK_META.current =
      CURRENT_TASK_META[componentIdx] = { taskID, componentIdx };
      return await fn();
    } catch (err) {
      _debugLog("error while executing async callee/callback", {
        ...args,
        err,
      });
      throw err;
    } finally {
      CURRENT_TASK_META[componentIdx] = null;
      if (CURRENT_TASK_META.current?.taskID === taskID) {
        CURRENT_TASK_META.current = null;
      }
    }
  }
  
  class AsyncTask {
    static _ID = 0n;
    
    static State = {
      INITIAL: 'initial',
      CANCELLED: 'cancelled',
      CANCEL_PENDING: 'cancel-pending',
      CANCEL_DELIVERED: 'cancel-delivered',
      RESOLVED: 'resolved',
    }
    
    static BlockResult = {
      CANCELLED: 'block.cancelled',
      NOT_CANCELLED: 'block.not-cancelled',
    }
    
    #id;
    #componentIdx;
    #state;
    #isAsync;
    #isManualAsync;
    #callingWasmExport = true;
    #lockFreeEntry = false;
    #preserveFutureResult;
    #entryFnName = null;
    
    #onResolveHandlers = [];
    #progressWaiters = [];
    #completionPromise = null;
    #completionValue;
    #completionReady = false;
    #settleCompletionPromise;
    #rejected = false;
    
    #exitPromise = null;
    #onExitHandlers = [];
    
    #memoryIdx = null;
    #memory = null;
    
    #callbackFn = null;
    #callbackFnName = null;
    
    #postReturnFn = null;
    
    #getCalleeParamsFn = null;
    #calleeIsAsync = null;
    #admissionTicket = null;
    #funcTypeIsAsync = false;
    #returnResultTypeIdx = null;
    
    #stringEncoding = null;
    
    #parentSubtask = null;
    
    #errHandling;
    
    #backpressurePromise;
    #backpressureWaiters = 0n;
    
    #returnLowerFns = null;
    
    #resourceScopeId;
    #resourceBorrowCount = 0;
    #resourceLenders = [];
    #resourceScopeExited = false;
    
    #subtasks = [];
    
    #entered = false;
    #exited = false;
    #errored = null;
    
    cancelled = false;
    cancelRequested = false;
    alwaysTaskReturn = false;
    
    returnCalls =  0;
    storage = [0, 0];
    tmpRetI64HighBits = 0|0;
    
    constructor(opts) {
      this.#id = ++AsyncTask._ID;
      this.#resourceScopeId = ++RESOURCE_SCOPE_ID;
      RESOURCE_SCOPE_TASKS.set(this.#resourceScopeId, this);
      
      if (opts?.componentIdx === undefined) {
        throw new TypeError('missing component id during task creation');
      }
      this.#componentIdx = opts.componentIdx;
      
      this.#state = AsyncTask.State.INITIAL;
      this.#isAsync = opts?.isAsync ?? false;
      this.#isManualAsync = opts?.isManualAsync ?? false;
      this.#preserveFutureResult = opts?.preserveFutureResult ?? false;
      this.#entryFnName = opts.entryFnName;
      // Tasks that execute guest slices (export calls, fused
      // callees) default to true; import-handler tasks pass false
      // explicitly (they run host code nested inside the caller's
      // already-locked slice).
      this.#callingWasmExport = opts?.callingWasmExport !== false;
      
      const {
        promise: completionPromise,
        resolve: resolveCompletionPromise,
        reject: rejectCompletionPromise,
      } = promiseWithResolvers();
      this.#completionPromise = completionPromise;
      // A nested rejection can reach the root task while its Wasm
      // entrypoint is still suspended, before the export wrapper awaits
      // this promise. Mark it handled immediately while preserving the
      // original rejected promise for the eventual caller.
      completionPromise.catch(() => {});
      
      let completionSettled = false;
      const settleCompletionPromise = () => {
        if (completionSettled || !this.#completionReady) { return; }
        completionSettled = true;
        if (this.#errored !== null) {
          rejectCompletionPromise(this.#errored);
        } else if (this.#rejected) {
          rejectCompletionPromise(this.#completionValue);
        } else if (
        this.#preserveFutureResult
        && this.#completionValue instanceof FutureValue
        ) {
          this.#completionValue.resolveAsValue(resolveCompletionPromise);
        } else {
          resolveCompletionPromise(this.#completionValue);
        }
      };
      
      this.#settleCompletionPromise = settleCompletionPromise;
      this.#onResolveHandlers.push((results) => {
        if (this.#parentSubtask !== null) { return; }
        if (!this.#isAsync && !this.#isManualAsync) { return; }
        this.#completionValue = results;
        this.#completionReady = true;
        // Publish after the current guest slice returns, so a trap
        // in that slice can still reject the call. Do not wait for
        // task exit: detached work may require further host calls
        // or consumption of a returned resource's stream.
      });
      
      const {
        promise: exitPromise,
        resolve: resolveExitPromise,
        reject: rejectExitPromise,
      } = promiseWithResolvers();
      this.#exitPromise = exitPromise;
      
      this.#onExitHandlers.push(() => {
        if (this.#parentSubtask === null && (this.#isAsync || this.#isManualAsync)) {
          settleCompletionPromise();
        }
        resolveExitPromise();
      });
      
      if (opts.callbackFn) { this.#callbackFn = opts.callbackFn; }
      if (opts.callbackFnName) { this.#callbackFnName = opts.callbackFnName; }
      
      if (opts.getCalleeParamsFn) { this.#getCalleeParamsFn = opts.getCalleeParamsFn; }
      if (opts.stringEncoding) { this.#stringEncoding = opts.stringEncoding; }
      
      if (opts.parentSubtask) { this.#parentSubtask = opts.parentSubtask; }
      
      
      if (opts.errHandling) { this.#errHandling = opts.errHandling; }
    }
    
    taskState() { return this.#state; }
    id() { return this.#id; }
    componentIdx() { return this.#componentIdx; }
    entryFnName() { return this.#entryFnName; }
    
    resourceScopeId() { return this.#resourceScopeId; }
    
    addBorrowedHandle() {
      if (this.#resourceScopeExited) {
        throw new Error('cannot add a borrow to an exited resource scope');
      }
      this.#resourceBorrowCount++;
    }
    
    removeBorrowedHandle() {
      if (this.#resourceBorrowCount === 0) {
        throw new Error('resource borrow count underflow');
      }
      this.#resourceBorrowCount--;
    }
    
    addResourceLender(table, handle) {
      if (this.#resourceScopeExited) {
        throw new Error('cannot add a lender to an exited resource scope');
      }
      this.#resourceLenders.push({ table, handle });
    }
    
    validateResourceBorrowScope() {
      if (this.#resourceScopeExited) { return; }
      if (this.#resourceBorrowCount !== 0) {
        throw new WebAssemblyRuntimeError('borrow handles still remain at the end of the call');
      }
      for (const { table, handle } of this.#resourceLenders) {
        const idx = handle << 1;
        const lendCount = table[idx];
        if (!Number.isInteger(lendCount) || lendCount <= 0 || lendCount >= 2**30) {
          throw new Error('invalid resource lender state at scope exit');
        }
        table[idx] = lendCount - 1;
      }
      this.#resourceLenders = [];
      this.#resourceScopeExited = true;
      RESOURCE_SCOPE_TASKS.delete(this.#resourceScopeId);
    }
    
    completionPromise() { return this.#completionPromise; }
    settleCompletion() { this.#settleCompletionPromise(); }
    exitPromise() { return this.#exitPromise; }
    
    waitForProgress() {
      const { promise, resolve } = promiseWithResolvers();
      this.#progressWaiters.push(resolve);
      return promise;
    }
    
    notifyProgress() {
      const waiters = this.#progressWaiters;
      this.#progressWaiters = [];
      for (const resolve of waiters) { resolve(); }
    }
    
    isAsync() { return this.#isAsync; }
    isManualAsync() { return this.#isManualAsync; }
    isSync() { return !this.isAsync(); }
    
    getErrHandling() { return this.#errHandling; }
    
    hasCallback() { return this.#callbackFn !== null; }
    
    getReturnMemoryIdx() { return this.#memoryIdx; }
    setReturnMemoryIdx(idx) {
      if (idx === null) { return; }
      this.#memoryIdx = idx;
    }
    
    getReturnMemory() { return this.#memory; }
    setReturnMemory(m) {
      if (m === null) { return; }
      this.#memory = m;
    }
    
    setReturnLowerFns(fns) { this.#returnLowerFns = fns; }
    getReturnLowerFns() { return this.#returnLowerFns; }
    
    setCalleeIsAsync(value) {
      if (typeof value !== 'boolean') { throw new TypeError('callee async state must be a boolean'); }
      this.#calleeIsAsync = value;
    }
    
    setParentSubtask(subtask) {
      if (!subtask || !(subtask instanceof AsyncSubtask)) { return }
      if (this.#parentSubtask) { throw new Error('parent subtask can only be set once'); }
      this.#parentSubtask = subtask;
    }
    
    getParentSubtask() { return this.#parentSubtask; }
    
    // TODO(threads): this is very inefficient, we can pass along a root task,
    // and ideally do not need this once thread support is in place
    getRootTask() {
      let currentSubtask = this.getParentSubtask();
      let task = this;
      while (currentSubtask) {
        task = currentSubtask.getParentTask();
        currentSubtask = task.getParentSubtask();
      }
      return task;
    }
    
    setPostReturnFn(f) {
      if (!f) { return; }
      if (this.#postReturnFn) { throw new Error('postReturn fn can only be set once'); }
      this.#postReturnFn = f;
    }
    
    setCallbackFn(f, name) {
      if (!f) { return; }
      if (this.#callbackFn) { throw new Error('callback fn can only be set once'); }
      this.#callbackFn = f;
      this.#callbackFnName = name;
    }
    
    getCallbackFnName() {
      if (!this.#callbackFnName) { return undefined; }
      return this.#callbackFnName;
    }
    
    runCallbackFn(...args) {
      if (!this.#callbackFn) { throw new Error('no callback function has been set for task'); }
      if (this.#callbackFn._jcoMaySuspend === false) {
        return _withGlobalCurrentTaskMeta({
          taskID: this.#id,
          componentIdx: this.#componentIdx,
          fn: () => this.#callbackFn.apply(null, args),
        });
      }
      return _withGlobalCurrentTaskMetaAsync({
        taskID: this.#id,
        componentIdx: this.#componentIdx,
        fn: () => { return this.#callbackFn.apply(null, args); }
      });
    }
    
    getCalleeParams() {
      if (!this.#getCalleeParamsFn) { throw new Error('missing/invalid getCalleeParamsFn'); }
      return this.#getCalleeParamsFn();
    }
    
    // Legacy manually-async exports are sync-typed in the component
    // but use JSPI precisely so their guest stack may suspend.
    // Canonical ABI: only sync-typed callees may not block (`canon_lift`);
    // an async-lifted callee may, even when called through a sync lowering.
    mayBlock() { return this.isAsync() || this.isManualAsync() || this.isResolvedState() || this.#funcTypeIsAsync }
    // (an async-typed function may block however it was lifted)
    setFuncTypeIsAsync(v) { this.#funcTypeIsAsync = v; }
    // The interned result type of the task's function (checked by `task.return`)
    setReturnResultTypeIdx(v) { this.#returnResultTypeIdx = v; }
    returnResultTypeIdx() { return this.#returnResultTypeIdx; }
    
    mayEnter(task) {
      const cstate = getOrCreateAsyncState(this.#componentIdx);
      if (cstate.hasBackpressure()) {
        _debugLog('[AsyncTask#mayEnter()] disallowed due to backpressure', { taskID: this.#id });
        return false;
      }
      if (!cstate.callingSyncImport()) {
        _debugLog('[AsyncTask#mayEnter()] disallowed due to sync import call', { taskID: this.#id });
        return false;
      }
      const callingSyncExportWithSyncPending = cstate.callingSyncExport && !task.isAsync;
      if (!callingSyncExportWithSyncPending) {
        _debugLog('[AsyncTask#mayEnter()] disallowed due to sync export w/ sync pending', { taskID: this.#id });
        return false;
      }
      return true;
    }
    
    enterSync() {
      if (this.needsExclusiveLock()) {
        const cstate = getOrCreateAsyncState(this.#componentIdx);
        if (!cstate.isExclusivelyLocked()) {
          cstate.exclusiveLock(this.#id);
        } else {
          // A host-called sync export arriving while another
          // task's slice holds the lock: synchronous entry
          // cannot wait, and historically this entry silently
          // stole the hold. Run without the lock instead --
          // the holder's bookkeeping stays intact and its
          // release still pairs
          this.#lockFreeEntry = true;
          _debugLog('[AsyncTask#enterSync()] entering without exclusive lock', {
            taskID: this.#id,
            componentIdx: this.#componentIdx,
          });
        }
      }
      return true;
    }
    
    tryEnter() {
      if (this.#entered) {
        throw new Error(`task with ID [${this.#id}] should not be entered twice`);
      }
      
      if (this.deliverPendingCancel({ cancellable: true })) {
        this.cancel();
        return false;
      }
      
      const cstate = getOrCreateAsyncState(this.#componentIdx);
      if (this.isSync()) {
        this.#entered = true;
        return true;
      }
      if (cstate.hasBackpressure()) { return null; }
      // Entries already queued for this instance go first.
      if (cstate.hasPendingAdmissions()) { return null; }
      if (this.needsExclusiveLock()) {
        if (cstate.isExclusivelyLocked()) { return null; }
        cstate.exclusiveLock(this.#id);
      }
      
      if (this.deliverPendingCancel({ cancellable: true })) {
        cstate.exclusiveRelease(this.#id);
        this.cancel();
        return false;
      }
      
      this.#entered = true;
      return true;
    }
    
    async enter(opts) {
      _debugLog('[AsyncTask#enter()] args', {
        taskID: this.#id,
        componentIdx: this.#componentIdx,
        subtaskID: this.getParentSubtask()?.id(),
        args: opts,
        entryFnName: this.#entryFnName,
      });
      
      if (this.#entered) {
        throw new Error(`task with ID [${this.#id}] should not be entered twice`);
      }
      
      // If cancellation was requested before the task was entered, resolve
      // as cancelled without ever running guest code
      if (this.deliverPendingCancel({ cancellable: true })) {
        this.cancel();
        return false;
      }
      
      const cstate = getOrCreateAsyncState(this.#componentIdx);
      
      if (opts?.isHost) {
        this.#entered = true;
        // A guest task may be synchronously blocked in this
        // host entry. Propagate that boundary so an async
        // cancellation driver can yield BLOCKED while the host
        // operation is outstanding.
        const parentTask = this.#parentSubtask?.getParentTask();
        if (
        parentTask?.taskState() === AsyncTask.State.CANCEL_DELIVERED
        || (parentTask && !parentTask.hasCallback())
        ) {
          parentTask.notifyProgress();
        }
        return this.#entered;
      }
      
      // NOTE: concurrent task lifetimes within one component instance are
      // permitted by the Component Model: entry is governed by the
      // backpressure and exclusive-lock checks below (the lock is held per
      // execution slice, not for the task's lifetime).
      //
      // Serializing entire task lifetimes here (the former "execution slot" queue)
      // deadlocks pipelines where a parked long-lived task's progress depends on a
      // later entry into the same component.
      
      // If a task is synchronous then we can avoid component-relevant
      // tracking and immediately enter.
      if (this.isSync()) {
        this.#entered = true;
        
        // TODO(breaking): remove once manually-specifying async fns is removed
        // It is currently possible for an actually sync export to be specified
        // as async via JSPI
        if (this.#isManualAsync) {
          if (this.needsExclusiveLock()) { await cstate.acquireExclusiveLock(this.#id); }
        }
        
        return this.#entered;
      }
      
      // Enter in the order the calls were made: queue behind every
      // earlier entry into this instance, whatever it waits for.
      const ticket = cstate.takeAdmissionTicket(this.#id);
      this.#admissionTicket = ticket;
      let entered = false;
      try {
        entered = await this.#enterQueued(cstate, ticket);
        return entered;
      } finally {
        // An entered task keeps the slot until its first slice ends
        // (`endFirstSlice`): the next call is admitted once this one
        // returned, blocked or trapped, as `Store.invoke` runs a call.
        if (!entered) { this.endFirstSlice(); }
      }
    }
    
    // The first slice of this task ended (it returned, blocked or trapped):
    // the next entry into the instance may be admitted (Canonical ABI
    // `Store.invoke` runs a call until it first blocks or returns).
    endFirstSlice() {
      const ticket = this.#admissionTicket;
      if (ticket === null) { return; }
      this.#admissionTicket = null;
      getOrCreateAsyncState(this.#componentIdx).releaseAdmissionTicket(ticket);
    }
    
    async #enterQueued(cstate, ticket) {
      await cstate.waitForAdmissionTurn(ticket);
      // Cancelled before it started while it was queued: the task was
      // retired already and must not park in a wait as a dead entry.
      if (this.isResolvedState() || this.isCancelled()) { return false; }
      
      // Wait until there is no backpressure *and* the exclusive lock (if
      // needed) is ours. Backpressure can be set while we wait for the
      // lock (by the task holding it), so it's checked again once the lock
      // is acquired, as the Canonical ABI's `enter_implicit_thread` waits
      // for both together.
      while (true) {
        if (cstate.hasBackpressure()) {
          cstate.addBackpressureWaiter();
          
          const result = await this.waitUntil({
            readyFn: () => {
              return !cstate.hasBackpressure();
            },
            cancellable: true,
          });
          
          cstate.removeBackpressureWaiter();
          
          if (!result || this.isCancelled()) {
            if (!this.isResolvedState()) { this.cancel(); }
            return false;
          }
        }
        
        // Acquire the per-slice exclusive lock (FIFO-queued when
        // contended); the first slice runs under this hold and the
        // driver loop releases/re-acquires it per slice thereafter.
        if (this.needsExclusiveLock()) {
          await cstate.acquireExclusiveLock(this.#id);
          if (cstate.hasBackpressure()) {
            cstate.exclusiveRelease(this.#id);
            continue;
          }
        }
        break;
      }
      
      // The store may have trapped (e.g. a deadlock was detected) while
      // this task waited to enter: it must not run, and its call fails
      // with that trap.
      try {
        cstate.throwIfInterrupted();
      } catch (err) {
        cstate.exclusiveRelease(this.#id);
        this.setErrored(err);
        return false;
      }
      
      // Cancellation-before-start may resolve this task while its
      // queued lock acquisition is still pending. Acquiring the lock
      // does not make the already-resolved task runnable again.
      if (this.isResolvedState() || this.isCancelled()) {
        cstate.exclusiveRelease(this.#id);
        return false;
      }
      
      // Cancellation can be requested while entry is waiting for
      // backpressure or its exclusive lock. Do not execute the guest
      // after acquiring a lock for a task that should no longer start.
      if (this.deliverPendingCancel({ cancellable: true })) {
        cstate.exclusiveRelease(this.#id);
        this.cancel();
        return false;
      }
      
      this.#entered = true;
      return this.#entered;
    }
    
    isRunningState() { return this.#state !== AsyncTask.State.RESOLVED; }
    isResolvedState() { return this.#state === AsyncTask.State.RESOLVED; }
    isResolved() { return this.#state === AsyncTask.State.RESOLVED; }
    isExited() { return this.#exited; }
    
    async waitUntil(opts) {
      const { readyFn, cancellable } = opts;
      _debugLog('[AsyncTask#waitUntil()] args', { taskID: this.#id, args: { cancellable } });
      
      // TODO(fix): check for cancel
      // TODO(fix): determinism
      // TODO(threads): add this thread to waiting list
      
      const keepGoing = await this.suspendUntil({
        readyFn,
        cancellable,
      });
      
      return keepGoing;
    }
    
    async yieldUntil(opts) {
      const { readyFn, cancellable } = opts;
      _debugLog('[AsyncTask#yieldUntil()]', {
        taskID: this.#id,
        args: {
          cancellable,
        },
        componentIdx: this.#componentIdx,
      });
      
      // A callback YIELD is an explicit request to let other work run.
      // Unlike waits whose condition is already ready, it must always
      // suspend for at least one scheduler turn.
      const keepGoing = await this.immediateSuspend({ readyFn, cancellable });
      if (keepGoing) {
        return {
          code: ASYNC_EVENT_CODE.NONE,
          payload0: 0,
          payload1: 0,
        };
      }
      
      return {
        code: ASYNC_EVENT_CODE.TASK_CANCELLED,
        payload0: 0,
        payload1: 0,
      };
    }
    
    async suspendUntil(opts) {
      const { cancellable, readyFn } = opts;
      _debugLog('[AsyncTask#suspendUntil()] args', {
        taskID: this.#id,
        args: {
          cancellable,
        },
        componentIdx: this.#componentIdx,
      });
      
      const pendingCancelled = this.deliverPendingCancel({ cancellable });
      if (pendingCancelled) { return false; }
      
      const completed = await this.immediateSuspendUntil({ readyFn, cancellable });
      return completed;
    }
    
    suspendUntilCallback(opts, onResume) {
      const { cancellable, readyFn } = opts;
      if (this.deliverPendingCancel({ cancellable })) {
        onResume(false);
        return;
      }
      
      const cstate = getOrCreateAsyncState(this.#componentIdx);
      cstate.suspendTask({
        task: this,
        cancellable,
        readyFn: () => {
          if (cancellable && this.#state === AsyncTask.State.CANCEL_PENDING) {
            return true;
          }
          return readyFn();
        },
        onResume: (keepGoing) => {
          if (keepGoing && this.deliverPendingCancel({ cancellable })) {
            keepGoing = false;
          }
          onResume(keepGoing);
        },
      });
    }
    
    // TODO(threads): equivalent to thread.suspend_until()
    async immediateSuspendUntil(opts) {
      const { cancellable, readyFn } = opts;
      _debugLog('[AsyncTask#immediateSuspendUntil()] args', {
        args: {
          cancellable,
          readyFn,
        },
        taskID: this.#id,
        componentIdx: this.#componentIdx,
      });
      
      const ready = readyFn();
      if (ready && ASYNC_DETERMINISM === 'random') {
        const coinFlip = _coinFlip();
        if (coinFlip) { return true }
      }
      
      const keepGoing = await this.immediateSuspend({ cancellable, readyFn });
      return keepGoing;
    }
    
    async immediateSuspend(opts) { // NOTE: equivalent to thread.suspend()
    // A task that already resolved (via `task.return`) has delivered
    // its result: a caller must not wait for this block to end
    // (Canonical ABI: `on_resolve` runs at `task.return`).
    this.settleCompletion();
    // TODO(threads): store readyFn on the thread
    const { cancellable, readyFn } = opts;
    _debugLog('[AsyncTask#immediateSuspend()] args', { cancellable, readyFn });
    
    const pendingCancelled = this.deliverPendingCancel({ cancellable });
    if (pendingCancelled) { return false; }
    
    const cstate = getOrCreateAsyncState(this.#componentIdx);
    const keepGoing = await cstate.suspendTask({
      task: this,
      cancellable,
      readyFn: () => {
        // A pending cancellation request wakes cancellable waits
        if (cancellable && this.#state === AsyncTask.State.CANCEL_PENDING) {
          return true;
        }
        return readyFn();
      },
    });
    if (keepGoing && this.deliverPendingCancel({ cancellable })) { return false; }
    return keepGoing;
  }
  
  deliverPendingCancel(opts) {
    const { cancellable } = opts;
    _debugLog('[AsyncTask#deliverPendingCancel()]', {
      args: { cancellable },
      taskID: this.#id,
      componentIdx: this.#componentIdx,
    });
    
    if (cancellable && this.#state === AsyncTask.State.CANCEL_PENDING) {
      this.#state = AsyncTask.State.CANCEL_DELIVERED;
      return true;
    }
    
    return false;
  }
  
  isCancelled() { return this.cancelled }
  cancellationRequested() { return this.cancelRequested; }
  
  // Request cooperative cancellation of this task, called on behalf of a
  // supertask performing `subtask.cancel` on the subtask this task backs.
  //
  // The request is delivered at this task's next cancellable wait
  // (see suspendUntil/immediateSuspend), at which point the task is
  // expected to acknowledge via `task.cancel` or still resolve via
  // `task.return`.
  requestCancellation() {
    _debugLog('[AsyncTask#requestCancellation()] args', {
      taskID: this.#id,
      componentIdx: this.#componentIdx,
      state: this.#state,
    });
    if (this.isResolvedState() || this.cancelRequested) { return; }
    this.cancelRequested = true;
    if (this.#state === AsyncTask.State.INITIAL) {
      this.#state = AsyncTask.State.CANCEL_PENDING;
      // A task still waiting for backpressure or its
      // initial instance lock has no guest thread to
      // resume. Cancellation is therefore delivered
      // and acknowledged eagerly as
      // CANCELLED_BEFORE_STARTED.
      if (!this.#entered) {
        this.deliverPendingCancel({ cancellable: true });
        this.cancel();
        
        const cstate = getOrCreateAsyncState(this.#componentIdx);
        // `enter()` may already be parked either in the scheduler's
        // explicit-backpressure wait or in the exclusive-lock FIFO.
        // Wake/remove that entry work now so it cannot retain a timer,
        // waiter count, or lock-queue slot after cancellation.
        cstate.resumeTaskByID(this.#id);
        cstate.cancelExclusiveLockWaiter(this.#id);
        
        // No guest thread was registered, so no driver loop will call
        // `exit()`. Retire the task's JS bookkeeping explicitly.
        this.exit({ skipExclusiveLockCheck: true });
        return;
      }
    }
    // Nudge the component's tick loop so that any suspended cancellable
    // wait observes the pending cancellation promptly
    getOrCreateAsyncState(this.#componentIdx).runTickLoop();
  }
  
  cancel(args) {
    _debugLog('[AsyncTask#cancel()] args', { });
    if (this.taskState() !== AsyncTask.State.CANCEL_DELIVERED) {
      throw new Error('`task.cancel` called by task which has not been cancelled');
    }
    this.validateResourceBorrowScope();
    this.cancelled = true;
    // Cancelled tasks resolve with no value (spec: `Task.cancel` calls
    // `on_resolve(None)`); an explicit error is only present on the
    // host-driven rejection path (see `reject()`).
    this.onResolve(args?.error ?? null);
    this.#state = AsyncTask.State.RESOLVED;
    // A task cancelled before entry has no driver loop that can
    // report its exit. Entered tasks notify after releasing their
    // component slice in `exit()`.
    if (!this.#entered) { this.notifyProgress(); }
  }
  
  onResolve(taskValue) {
    const handlers = this.#onResolveHandlers;
    this.#onResolveHandlers = [];
    for (const f of handlers) {
      try {
        f(taskValue);
      } catch (err) {
        _debugLog("[AsyncTask#onResolve] error during task resolve handler", err);
        throw err;
      }
    }
    
    // Rejections are control-flow failures, not canonical ABI results.
    // Propagate them through the subtask chain without running return
    // lowering or post-return hooks for a successful result.
    if (this.#rejected) {
      this.#parentSubtask?.reject(taskValue);
      return;
    }
    
    // NOTE: if the parent subtask has already been resolved (e.g. it was
    // cancelled via `subtask.cancel` while this task was still pending),
    // this task's resolution must be discarded rather than delivered.
    const parentSubtaskPending = this.#parentSubtask && !this.#parentSubtask.isResolved();
    const taskReturned = !this.isCancelled();
    
    if (parentSubtaskPending && taskReturned) {
      const meta = this.#parentSubtask.getCallMetadata();
      // Run the rturn fn if it has not already been called -- this *should* have happened in
      // `task.return`, but some paths do not go through task.return (e.g. async lower of sync fn
      // which goes through prepare + async-start-call)
      if (meta.returnFn && !meta.returnFnCalled) {
        _debugLog('[AsyncTask#onResolve()] running returnFn', {
          componentIdx: this.#componentIdx,
          taskID: this.#id,
          subtaskID: this.#parentSubtask.id(),
        });
        const callerTask = this.#parentSubtask.getParentTask();
        _withGlobalCurrentTaskMeta({
          taskID: callerTask.id(),
          componentIdx: callerTask.componentIdx(),
          fn: () => meta.returnFn.apply(null, [taskValue, meta.resultPtr]),
        });
        meta.returnFnCalled = true;
      }
    }
    
    if (this.#postReturnFn && taskReturned) {
      _debugLog('[AsyncTask#onResolve()] running post return ', {
        componentIdx: this.#componentIdx,
        taskID: this.#id,
      });
      try {
        _withGlobalCurrentTaskMeta({
          taskID: this.#id,
          componentIdx: this.#componentIdx,
          fn: () => this.#postReturnFn(taskValue),
        });
      } catch (err) {
        _debugLog("[AsyncTask#onResolve] error during task resolve handler", err);
        throw err;
      }
    }
    
    if (parentSubtaskPending) {
      this.#parentSubtask.onResolve(taskValue);
    }
  }
  
  registerOnResolveHandler(f) {
    this.#onResolveHandlers.push(f);
  }
  
  isRejected() { return this.#rejected; }
  
  isErrored() { return this.#errored; }
  setErrored(err) {
    // Preserve the originating trap when unwinding through
    // additional guest frames produces secondary traps (often
    // an `unreachable` after a call which was expected to trap).
    if (this.#errored === null) { this.#errored = err; }
  }
  
  reject(taskErr) {
    _debugLog('[AsyncTask#reject()] args', {
      componentIdx: this.#componentIdx,
      taskID: this.#id,
      parentSubtask: this.#parentSubtask,
      parentSubtaskID: this.#parentSubtask?.id(),
      entryFnName: this.entryFnName(),
      callbackFnName: this.#callbackFnName,
      errMsg: taskErr.message,
    });
    
    this.setErrored(taskErr);
    if (this.#rejected) { return; }
    
    // A task may call `task.return` before its callback exits.
    // A trap in cleanup or spawned work must still reject the
    // host call and poison the enclosing task chain.
    if (this.isResolvedState()) {
      this.#rejected = true;
      this.#errored = taskErr;
      const parentTask = this.#parentSubtask?.getParentTask();
      if (parentTask) { parentTask.reject(taskErr); }
      return;
    }
    
    this.#rejected = true;
    this.cancelRequested = true;
    this.#state = AsyncTask.State.CANCEL_PENDING;
    const cancelled = this.deliverPendingCancel({ cancellable: true });
    
    // TODO: do cleanup here to reset the machinery so we can run again?
    
    this.cancel({ error: taskErr });
  }
  
  resolve(results) {
    _debugLog('[AsyncTask#resolve()] args', {
      componentIdx: this.#componentIdx,
      taskID: this.#id,
      entryFnName: this.entryFnName(),
      callbackFnName: this.#callbackFnName,
    });
    
    if (this.#state === AsyncTask.State.RESOLVED) {
      if (this.#errored !== null) { throw this.#errored; }
      throw new Error(`(component [${this.#componentIdx}]) task [${this.#id}]  is already resolved (did you forget to wait for an import?)`);
    }
    
    this.validateResourceBorrowScope();
    
    this.#state = AsyncTask.State.RESOLVED;
    
    switch (results.length) {
      case 0:
      this.onResolve(undefined);
      break;
      case 1:
      this.onResolve(results[0]);
      break;
      default:
      _debugLog('[AsyncTask#resolve()] unexpected number of results', {
        componentIdx: this.#componentIdx,
        results,
        taskID: this.#id,
        subtaskID: this.#parentSubtask?.id(),
        entryFnName: this.#entryFnName,
        callbackFnName: this.#callbackFnName,
      });
      throw new Error('unexpected number of results');
    }
  }
  
  exit(args) {
    _debugLog('[AsyncTask#exit()]', {
      componentIdx: this.#componentIdx,
      taskID: this.#id,
    });
    
    this.endFirstSlice();
    if (this.#exited)  { throw new Error("task has already exited"); }
    
    if (this.#state !== AsyncTask.State.RESOLVED) {
      // (Canonical ABI `Task.exit_implicit_thread`: a task must resolve before it exits)
      throw new WebAssemblyRuntimeError(`(component [${this.#componentIdx}]) task [${this.#id}] exited without resolution`);
    }
    
    this.validateResourceBorrowScope();
    
    const state = getOrCreateAsyncState(this.#componentIdx);
    if (!state) { throw new Error('missing async state for component [' + this.#componentIdx + ']'); }
    
    // Exempt the host from exclusive lock check
    if (this.#componentIdx !== -1 && !args?.skipExclusiveLockCheck && !this.#lockFreeEntry) {
      if (this.needsExclusiveLock() && !state.exclusivelyLockedBy(this.#id)) {
        throw new Error(`task [${this.#id}] exit: component [${this.#componentIdx}] should have been exclusively locked by it`);
      }
    }
    
    // Ownership-checked: releases only this task's own hold (a
    // task exiting while another task's slice holds the lock no
    // longer clears the foreign hold).
    state.exclusiveRelease(this.#id);
    this.notifyProgress();
    
    for (const f of this.#onExitHandlers) {
      try {
        f();
      } catch (err) {
        console.error("error during task exit handler", err);
        throw err;
      }
    }
    
    this.#exited = true;
    clearCurrentTask(this.#componentIdx, this.id());
  }
  
  needsExclusiveLock() {
    // Host (-1) tasks model host-side import handling: there is no
    // guest linear memory or executor state to protect, and host
    // calls from unrelated guest components would contend spuriously.
    if (this.#componentIdx === -1) { return false; }
    // Import-handler tasks (CallInterface) run host code nested
    // inside the calling guest slice, which already holds the
    // lock; only tasks that execute guest slices need it.
    if (!this.#callingWasmExport) { return false; }
    // A sync-lifted callee cannot be reentered until the whole
    // stackful call returns. This is the Component Model's
    // automatic-backpressure rule for async-lowered calls.
    return !this.#isAsync || this.hasCallback() || this.#calleeIsAsync === false;
  }
  
  createSubtask(args) {
    _debugLog('[AsyncTask#createSubtask()] args', args);
    const { componentIdx, childTask, callMetadata, fnName, isAsync, isManualAsync } = args;
    
    const cstate = getOrCreateAsyncState(this.#componentIdx);
    if (!cstate) {
      throw new Error(`invalid/missing async state for component idx [${componentIdx}]`);
    }
    
    const waitable = new Waitable({
      componentIdx: this.#componentIdx,
      target: `subtask (internal ID [${this.#id}])`,
    });
    
    const newSubtask = new AsyncSubtask({
      componentIdx,
      childTask,
      parentTask: this,
      callMetadata,
      isAsync,
      isManualAsync,
      fnName,
      waitable,
    });
    this.#subtasks.push(newSubtask);
    newSubtask.setTarget(`subtask (internal ID [${newSubtask.id()}], waitable [${waitable.idx()}], component [${componentIdx}])`);
    // The subtask gets a handle index in this task's table only once the
    // guest is given it (see `AsyncSubtask#ensureHandle`).
    return newSubtask;
  }
  
  getLatestSubtask() {
    return this.#subtasks.at(-1);
  }
  
  getSubtaskByWaitableRep(rep) {
    if (rep === undefined) { throw new TypeError('missing rep'); }
    return this.#subtasks.find(s => s.waitableRep() === rep);
  }
  
  currentSubtask() {
    _debugLog('[AsyncTask#currentSubtask()]');
    if (this.#subtasks.length === 0) { return undefined; }
    return this.#subtasks.at(-1);
  }
  
  removeSubtask(subtask) {
    if (this.#subtasks.length === 0) {
      throw new Error('cannot end current subtask: no current subtask');
    }
    this.#subtasks = this.#subtasks.filter(t => t !== subtask);
    return subtask;
  }
}

function createNewCurrentTask(args) {
  _debugLog('[createNewCurrentTask()] args', args);
  const {
    componentIdx,
    isAsync,
    isManualAsync,
    preserveFutureResult,
    entryFnName,
    parentSubtaskID,
    callbackFnName,
    getCallbackFn,
    getParamsFn,
    stringEncoding,
    errHandling,
    getCalleeParamsFn,
    resultPtr,
    callingWasmExport,
  } = args;
  if (componentIdx === undefined || componentIdx === null) {
    throw new Error('missing/invalid component instance index while starting task');
  }
  let taskMetas = ASYNC_TASKS_BY_COMPONENT_IDX.get(componentIdx);
  const callbackFn = getCallbackFn ? getCallbackFn() : null;
  
  const newTask = new AsyncTask({
    componentIdx,
    isAsync,
    isManualAsync,
    preserveFutureResult,
    entryFnName,
    callbackFn,
    callbackFnName,
    stringEncoding,
    getCalleeParamsFn,
    resultPtr,
    errHandling,
    callingWasmExport,
  });
  
  const newTaskID = newTask.id();
  const newTaskMeta = { id: newTaskID, componentIdx, task: newTask };
  
  // NOTE: do not track host tasks
  ASYNC_CURRENT_TASK_IDS.push(newTaskID);
  ASYNC_CURRENT_COMPONENT_IDXS.push(componentIdx);
  
  if (!taskMetas) {
    taskMetas = [newTaskMeta];
    ASYNC_TASKS_BY_COMPONENT_IDX.set(componentIdx, [newTaskMeta]);
  } else {
    taskMetas.push(newTaskMeta);
  }
  
  return [newTask, newTaskID];
}

const CURRENT_TASK_MAY_BLOCK= typeof WebAssembly !== 'undefined' ? new WebAssembly.Global({ value: 'i32', mutable: true }, 0) : false;


function _checkMayLeave(componentIdx) {
  if (INSTANCE_FLAGS.get(componentIdx)?.value !== 1) {
    throw new WebAssemblyRuntimeError('cannot leave component instance');
  }
}

function _guardMayLeave(componentIdx, fn) {
  return function (...args) {
    _checkMayLeave(componentIdx);
    return fn.apply(this, args);
  };
}

function _recordTrap(componentIdx, err, convertsRangeErrors = false) {
  // A built-in reading or writing guest memory past its end fails with a
  // DataView RangeError: that is the Canonical ABI's out-of-bounds trap.
  if (convertsRangeErrors && err instanceof RangeError) {
    err = new WebAssemblyRuntimeError('out of bounds memory access');
  }
  if (err instanceof WebAssemblyRuntimeError) {
    // (a trampoline without a static instance records against the
    // component whose guest code is running)
    const idx = componentIdx ?? CURRENT_TASK_META.current?.componentIdx;
    if (idx !== undefined && idx !== null) {
      getOrCreateAsyncState(idx).markTrapped(err);
    }
  }
  return err;
}

function _guardTrap(componentIdx, fn, convertsRangeErrors = false) {
  return function (...args) {
    try {
      return fn.apply(this, args);
    } catch (err) {
      throw _recordTrap(componentIdx, err, convertsRangeErrors);
    }
  };
}

const base64Compile = str => WebAssembly.compile(
typeof Buffer !== 'undefined'
? Buffer.from(str, 'base64')
: Uint8Array.from(atob(str), b => b.charCodeAt(0))
);


const isNode = typeof process !== 'undefined' && process.versions && process.versions.node;
let _fs;
async function fetchCompile (url) {
  if (isNode) {
    _fs = _fs || await import('node:fs/promises');
    return WebAssembly.compile(await _fs.readFile(url));
  }
  return fetch(url).then(WebAssembly.compileStreaming);
}

const symbolRscHandle = Symbol('handle');

const HANDLE_TABLES= [];


function finalizationRegistryCreate (unregister) {
  if (typeof FinalizationRegistry === 'undefined') {
    return { unregister () {} };
  }
  return new FinalizationRegistry(unregister);
}

class ComponentError extends Error {
  constructor (value) {
    const enumerable = typeof value !== 'string';
    super(enumerable ? `${String(value)} (see error.payload)` : value);
    Object.defineProperty(this, 'payload', { value, enumerable });
  }
}

function throwInvalidBool() {
  throw new TypeError('invalid variant discriminant for bool');
}

const instantiateCore = WebAssembly.instantiate;


let exports0;
let exports1;
let exports2;
let memory0;
let realloc0;
let realloc0Async;
let postReturn0;
let postReturn0Async;
let postReturn1;
let postReturn1Async;
let postReturn2;
let postReturn2Async;
let postReturn3;
let postReturn3Async;
let postReturn4;
let postReturn4Async;
let postReturn5;
let postReturn5Async;
let exports1SerializeInst;

function serializeInst(arg0) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'exports1SerializeInst',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(1);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        
        var encodeRes = _utf8AllocateAndEncode(arg0, realloc0, memory0);
        var ptr0= encodeRes.ptr;
        var len0 = encodeRes.len;
        
        _debugLog('[iface="serialize-inst", function="serialize-inst"][Instruction::CallWasm] enter', {
          funcName: 'serialize-inst',
          paramCount: 2,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => exports1SerializeInst(ptr0, len0),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant3;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            var ptr1 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true) >>> 0;
            var len1 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true);
            if (ptr1 < 0 || len1 < 0 || len1 > 268435455 || ptr1 > memory0.buffer.byteLength || len1 > Math.floor((memory0.buffer.byteLength - ptr1) / 1)) throw new WebAssemblyRuntimeError('wasm trap: out of bounds memory access');
            if (ptr1 % 1 !== 0) throw new TypeError(`list pointer [${ptr1}] is not aligned to 1`);
            var result1 = new Uint8Array(memory0.buffer.slice(ptr1, ptr1 + len1 * 1));
            variant3= {
              tag: 'ok',
              val: result1
            };
            break;
          }
          case 1: {
            var ptr2 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true) >>> 0;
            var len2 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true);
            var result2 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr2, len2));
            variant3= {
              tag: 'err',
              val: result2
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="serialize-inst", function="serialize-inst"][Instruction::Return]', {
          funcName: 'serialize-inst',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant3;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn0(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let exports1DeserializeInst;

function deserializeInst(arg0) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'exports1DeserializeInst',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(3);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var val0 = arg0;
        var len0 = Array.isArray(val0) ? val0.length : val0.byteLength;
        var ptr0 = realloc0(0, 0, 1, len0 * 1);
        
        let valData0;
        const valLenBytes0 = len0 * 1;
        if (Array.isArray(val0)) {
          // Regular array likely containing numbers, write values to memory
          let offset = 0;
          const dv0 = new DataView(memory0.buffer);
          for (const v of val0) {
            _requireValidNumericPrimitive.bind(null, 'u8')(v);
            dv0.setUint8(ptr0+ offset, v, true);
            offset += 1;
          }
        } else {
          // TypedArray / ArrayBuffer-like, direct copy
          valData0 = new Uint8Array(val0.buffer || val0, val0.byteOffset, valLenBytes0);
          const out0 = new Uint8Array(memory0.buffer, ptr0, valLenBytes0);
          out0.set(valData0);
        }
        
        _debugLog('[iface="deserialize-inst", function="deserialize-inst"][Instruction::CallWasm] enter', {
          funcName: 'deserialize-inst',
          paramCount: 2,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => exports1DeserializeInst(ptr0, len0),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant3;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            var ptr1 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true) >>> 0;
            var len1 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true);
            var result1 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr1, len1));
            variant3= {
              tag: 'ok',
              val: result1
            };
            break;
          }
          case 1: {
            var ptr2 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true) >>> 0;
            var len2 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true);
            var result2 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr2, len2));
            variant3= {
              tag: 'err',
              val: result2
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="deserialize-inst", function="deserialize-inst"][Instruction::Return]', {
          funcName: 'deserialize-inst',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant3;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn0(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let exports1BlsSecretKeyGen;

function blsSecretKeyGen(arg0) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'exports1BlsSecretKeyGen',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(1);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var val0 = arg0;
        var len0 = Array.isArray(val0) ? val0.length : val0.byteLength;
        var ptr0 = realloc0(0, 0, 1, len0 * 1);
        
        let valData0;
        const valLenBytes0 = len0 * 1;
        if (Array.isArray(val0)) {
          // Regular array likely containing numbers, write values to memory
          let offset = 0;
          const dv0 = new DataView(memory0.buffer);
          for (const v of val0) {
            _requireValidNumericPrimitive.bind(null, 'u8')(v);
            dv0.setUint8(ptr0+ offset, v, true);
            offset += 1;
          }
        } else {
          // TypedArray / ArrayBuffer-like, direct copy
          valData0 = new Uint8Array(val0.buffer || val0, val0.byteOffset, valLenBytes0);
          const out0 = new Uint8Array(memory0.buffer, ptr0, valLenBytes0);
          out0.set(valData0);
        }
        
        _debugLog('[iface="bls-secret-key-gen", function="bls-secret-key-gen"][Instruction::CallWasm] enter', {
          funcName: 'bls-secret-key-gen',
          paramCount: 2,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => exports1BlsSecretKeyGen(ptr0, len0),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant3;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            var ptr1 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true) >>> 0;
            var len1 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true);
            if (ptr1 < 0 || len1 < 0 || len1 > 268435455 || ptr1 > memory0.buffer.byteLength || len1 > Math.floor((memory0.buffer.byteLength - ptr1) / 1)) throw new WebAssemblyRuntimeError('wasm trap: out of bounds memory access');
            if (ptr1 % 1 !== 0) throw new TypeError(`list pointer [${ptr1}] is not aligned to 1`);
            var result1 = new Uint8Array(memory0.buffer.slice(ptr1, ptr1 + len1 * 1));
            variant3= {
              tag: 'ok',
              val: result1
            };
            break;
          }
          case 1: {
            var ptr2 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true) >>> 0;
            var len2 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true);
            var result2 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr2, len2));
            variant3= {
              tag: 'err',
              val: result2
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="bls-secret-key-gen", function="bls-secret-key-gen"][Instruction::Return]', {
          funcName: 'bls-secret-key-gen',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant3;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn0(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let exports1BlsSecretFromSeedEip2333;

function blsSecretFromSeedEip2333(arg0, arg1) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'exports1BlsSecretFromSeedEip2333',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(1);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var val0 = arg0;
        var len0 = Array.isArray(val0) ? val0.length : val0.byteLength;
        var ptr0 = realloc0(0, 0, 1, len0 * 1);
        
        let valData0;
        const valLenBytes0 = len0 * 1;
        if (Array.isArray(val0)) {
          // Regular array likely containing numbers, write values to memory
          let offset = 0;
          const dv0 = new DataView(memory0.buffer);
          for (const v of val0) {
            _requireValidNumericPrimitive.bind(null, 'u8')(v);
            dv0.setUint8(ptr0+ offset, v, true);
            offset += 1;
          }
        } else {
          // TypedArray / ArrayBuffer-like, direct copy
          valData0 = new Uint8Array(val0.buffer || val0, val0.byteOffset, valLenBytes0);
          const out0 = new Uint8Array(memory0.buffer, ptr0, valLenBytes0);
          out0.set(valData0);
        }
        
        var val1 = arg1;
        var len1 = val1.length;
        var ptr1 = realloc0(0, 0, 4, len1 * 4);
        
        let valData1;
        const valLenBytes1 = len1 * 4;
        if (Array.isArray(val1)) {
          // Regular array likely containing numbers, write values to memory
          let offset = 0;
          const dv1 = new DataView(memory0.buffer);
          for (const v of val1) {
            _requireValidNumericPrimitive.bind(null, 'u32')(v);
            dv1.setUint32(ptr1+ offset, v, true);
            offset += 4;
          }
        } else {
          // TypedArray / ArrayBuffer-like, direct copy
          valData1 = new Uint8Array(val1.buffer || val1, val1.byteOffset, valLenBytes1);
          const out1 = new Uint8Array(memory0.buffer, ptr1, valLenBytes1);
          out1.set(valData1);
        }
        
        _debugLog('[iface="bls-secret-from-seed-eip2333", function="bls-secret-from-seed-eip2333"][Instruction::CallWasm] enter', {
          funcName: 'bls-secret-from-seed-eip2333',
          paramCount: 4,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => exports1BlsSecretFromSeedEip2333(ptr0, len0, ptr1, len1),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant4;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            var ptr2 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true) >>> 0;
            var len2 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true);
            if (ptr2 < 0 || len2 < 0 || len2 > 268435455 || ptr2 > memory0.buffer.byteLength || len2 > Math.floor((memory0.buffer.byteLength - ptr2) / 1)) throw new WebAssemblyRuntimeError('wasm trap: out of bounds memory access');
            if (ptr2 % 1 !== 0) throw new TypeError(`list pointer [${ptr2}] is not aligned to 1`);
            var result2 = new Uint8Array(memory0.buffer.slice(ptr2, ptr2 + len2 * 1));
            variant4= {
              tag: 'ok',
              val: result2
            };
            break;
          }
          case 1: {
            var ptr3 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true) >>> 0;
            var len3 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true);
            var result3 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr3, len3));
            variant4= {
              tag: 'err',
              val: result3
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="bls-secret-from-seed-eip2333", function="bls-secret-from-seed-eip2333"][Instruction::Return]', {
          funcName: 'bls-secret-from-seed-eip2333',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant4;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn0(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let exports1BlsPubkeyFromSecret;

function blsPubkeyFromSecret(arg0) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'exports1BlsPubkeyFromSecret',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(1);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var val0 = arg0;
        var len0 = Array.isArray(val0) ? val0.length : val0.byteLength;
        var ptr0 = realloc0(0, 0, 1, len0 * 1);
        
        let valData0;
        const valLenBytes0 = len0 * 1;
        if (Array.isArray(val0)) {
          // Regular array likely containing numbers, write values to memory
          let offset = 0;
          const dv0 = new DataView(memory0.buffer);
          for (const v of val0) {
            _requireValidNumericPrimitive.bind(null, 'u8')(v);
            dv0.setUint8(ptr0+ offset, v, true);
            offset += 1;
          }
        } else {
          // TypedArray / ArrayBuffer-like, direct copy
          valData0 = new Uint8Array(val0.buffer || val0, val0.byteOffset, valLenBytes0);
          const out0 = new Uint8Array(memory0.buffer, ptr0, valLenBytes0);
          out0.set(valData0);
        }
        
        _debugLog('[iface="bls-pubkey-from-secret", function="bls-pubkey-from-secret"][Instruction::CallWasm] enter', {
          funcName: 'bls-pubkey-from-secret',
          paramCount: 2,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => exports1BlsPubkeyFromSecret(ptr0, len0),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant3;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            var ptr1 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true) >>> 0;
            var len1 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true);
            if (ptr1 < 0 || len1 < 0 || len1 > 268435455 || ptr1 > memory0.buffer.byteLength || len1 > Math.floor((memory0.buffer.byteLength - ptr1) / 1)) throw new WebAssemblyRuntimeError('wasm trap: out of bounds memory access');
            if (ptr1 % 1 !== 0) throw new TypeError(`list pointer [${ptr1}] is not aligned to 1`);
            var result1 = new Uint8Array(memory0.buffer.slice(ptr1, ptr1 + len1 * 1));
            variant3= {
              tag: 'ok',
              val: result1
            };
            break;
          }
          case 1: {
            var ptr2 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true) >>> 0;
            var len2 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true);
            var result2 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr2, len2));
            variant3= {
              tag: 'err',
              val: result2
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="bls-pubkey-from-secret", function="bls-pubkey-from-secret"][Instruction::Return]', {
          funcName: 'bls-pubkey-from-secret',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant3;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn0(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let exports1BlsSign;

function blsSign(arg0, arg1) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'exports1BlsSign',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(1);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var val0 = arg0;
        var len0 = Array.isArray(val0) ? val0.length : val0.byteLength;
        var ptr0 = realloc0(0, 0, 1, len0 * 1);
        
        let valData0;
        const valLenBytes0 = len0 * 1;
        if (Array.isArray(val0)) {
          // Regular array likely containing numbers, write values to memory
          let offset = 0;
          const dv0 = new DataView(memory0.buffer);
          for (const v of val0) {
            _requireValidNumericPrimitive.bind(null, 'u8')(v);
            dv0.setUint8(ptr0+ offset, v, true);
            offset += 1;
          }
        } else {
          // TypedArray / ArrayBuffer-like, direct copy
          valData0 = new Uint8Array(val0.buffer || val0, val0.byteOffset, valLenBytes0);
          const out0 = new Uint8Array(memory0.buffer, ptr0, valLenBytes0);
          out0.set(valData0);
        }
        
        var val1 = arg1;
        var len1 = Array.isArray(val1) ? val1.length : val1.byteLength;
        var ptr1 = realloc0(0, 0, 1, len1 * 1);
        
        let valData1;
        const valLenBytes1 = len1 * 1;
        if (Array.isArray(val1)) {
          // Regular array likely containing numbers, write values to memory
          let offset = 0;
          const dv1 = new DataView(memory0.buffer);
          for (const v of val1) {
            _requireValidNumericPrimitive.bind(null, 'u8')(v);
            dv1.setUint8(ptr1+ offset, v, true);
            offset += 1;
          }
        } else {
          // TypedArray / ArrayBuffer-like, direct copy
          valData1 = new Uint8Array(val1.buffer || val1, val1.byteOffset, valLenBytes1);
          const out1 = new Uint8Array(memory0.buffer, ptr1, valLenBytes1);
          out1.set(valData1);
        }
        
        _debugLog('[iface="bls-sign", function="bls-sign"][Instruction::CallWasm] enter', {
          funcName: 'bls-sign',
          paramCount: 4,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => exports1BlsSign(ptr0, len0, ptr1, len1),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant4;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            var ptr2 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true) >>> 0;
            var len2 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true);
            if (ptr2 < 0 || len2 < 0 || len2 > 268435455 || ptr2 > memory0.buffer.byteLength || len2 > Math.floor((memory0.buffer.byteLength - ptr2) / 1)) throw new WebAssemblyRuntimeError('wasm trap: out of bounds memory access');
            if (ptr2 % 1 !== 0) throw new TypeError(`list pointer [${ptr2}] is not aligned to 1`);
            var result2 = new Uint8Array(memory0.buffer.slice(ptr2, ptr2 + len2 * 1));
            variant4= {
              tag: 'ok',
              val: result2
            };
            break;
          }
          case 1: {
            var ptr3 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true) >>> 0;
            var len3 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true);
            var result3 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr3, len3));
            variant4= {
              tag: 'err',
              val: result3
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="bls-sign", function="bls-sign"][Instruction::Return]', {
          funcName: 'bls-sign',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant4;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn0(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let exports1BlsVerify;

function blsVerify(arg0, arg1, arg2) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'exports1BlsVerify',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(7);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var val0 = arg0;
        var len0 = Array.isArray(val0) ? val0.length : val0.byteLength;
        var ptr0 = realloc0(0, 0, 1, len0 * 1);
        
        let valData0;
        const valLenBytes0 = len0 * 1;
        if (Array.isArray(val0)) {
          // Regular array likely containing numbers, write values to memory
          let offset = 0;
          const dv0 = new DataView(memory0.buffer);
          for (const v of val0) {
            _requireValidNumericPrimitive.bind(null, 'u8')(v);
            dv0.setUint8(ptr0+ offset, v, true);
            offset += 1;
          }
        } else {
          // TypedArray / ArrayBuffer-like, direct copy
          valData0 = new Uint8Array(val0.buffer || val0, val0.byteOffset, valLenBytes0);
          const out0 = new Uint8Array(memory0.buffer, ptr0, valLenBytes0);
          out0.set(valData0);
        }
        
        var val1 = arg1;
        var len1 = Array.isArray(val1) ? val1.length : val1.byteLength;
        var ptr1 = realloc0(0, 0, 1, len1 * 1);
        
        let valData1;
        const valLenBytes1 = len1 * 1;
        if (Array.isArray(val1)) {
          // Regular array likely containing numbers, write values to memory
          let offset = 0;
          const dv1 = new DataView(memory0.buffer);
          for (const v of val1) {
            _requireValidNumericPrimitive.bind(null, 'u8')(v);
            dv1.setUint8(ptr1+ offset, v, true);
            offset += 1;
          }
        } else {
          // TypedArray / ArrayBuffer-like, direct copy
          valData1 = new Uint8Array(val1.buffer || val1, val1.byteOffset, valLenBytes1);
          const out1 = new Uint8Array(memory0.buffer, ptr1, valLenBytes1);
          out1.set(valData1);
        }
        
        var val2 = arg2;
        var len2 = Array.isArray(val2) ? val2.length : val2.byteLength;
        var ptr2 = realloc0(0, 0, 1, len2 * 1);
        
        let valData2;
        const valLenBytes2 = len2 * 1;
        if (Array.isArray(val2)) {
          // Regular array likely containing numbers, write values to memory
          let offset = 0;
          const dv2 = new DataView(memory0.buffer);
          for (const v of val2) {
            _requireValidNumericPrimitive.bind(null, 'u8')(v);
            dv2.setUint8(ptr2+ offset, v, true);
            offset += 1;
          }
        } else {
          // TypedArray / ArrayBuffer-like, direct copy
          valData2 = new Uint8Array(val2.buffer || val2, val2.byteOffset, valLenBytes2);
          const out2 = new Uint8Array(memory0.buffer, ptr2, valLenBytes2);
          out2.set(valData2);
        }
        
        _debugLog('[iface="bls-verify", function="bls-verify"][Instruction::CallWasm] enter', {
          funcName: 'bls-verify',
          paramCount: 6,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => exports1BlsVerify(ptr0, len0, ptr1, len1, ptr2, len2),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant5;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            var bool3 = dataView(memory0).getUint8(((ret >>> 0)) + 4, true);
            variant5= {
              tag: 'ok',
              val: bool3 == 0 ? false : (bool3 == 1 ? true : throwInvalidBool())
            };
            break;
          }
          case 1: {
            var ptr4 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true) >>> 0;
            var len4 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true);
            var result4 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr4, len4));
            variant5= {
              tag: 'err',
              val: result4
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="bls-verify", function="bls-verify"][Instruction::Return]', {
          funcName: 'bls-verify',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant5;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn1(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let exports1AggregateSigningMessage;

function aggregateSigningMessage(arg0, arg1, arg2, arg3) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'exports1AggregateSigningMessage',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(1);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        
        var encodeRes = _utf8AllocateAndEncode(arg0, realloc0, memory0);
        var ptr0= encodeRes.ptr;
        var len0 = encodeRes.len;
        
        
        var encodeRes = _utf8AllocateAndEncode(arg3, realloc0, memory0);
        var ptr1= encodeRes.ptr;
        var len1 = encodeRes.len;
        
        _debugLog('[iface="aggregate-signing-message", function="aggregate-signing-message"][Instruction::CallWasm] enter', {
          funcName: 'aggregate-signing-message',
          paramCount: 6,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => exports1AggregateSigningMessage(ptr0, len0, toUint64(arg1), arg2 ? 1 : 0, ptr1, len1),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant4;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            var ptr2 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true) >>> 0;
            var len2 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true);
            if (ptr2 < 0 || len2 < 0 || len2 > 268435455 || ptr2 > memory0.buffer.byteLength || len2 > Math.floor((memory0.buffer.byteLength - ptr2) / 1)) throw new WebAssemblyRuntimeError('wasm trap: out of bounds memory access');
            if (ptr2 % 1 !== 0) throw new TypeError(`list pointer [${ptr2}] is not aligned to 1`);
            var result2 = new Uint8Array(memory0.buffer.slice(ptr2, ptr2 + len2 * 1));
            variant4= {
              tag: 'ok',
              val: result2
            };
            break;
          }
          case 1: {
            var ptr3 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true) >>> 0;
            var len3 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true);
            var result3 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr3, len3));
            variant4= {
              tag: 'err',
              val: result3
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="aggregate-signing-message", function="aggregate-signing-message"][Instruction::Return]', {
          funcName: 'aggregate-signing-message',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant4;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn0(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let exports1BlsAggregateSignatures;

function blsAggregateSignatures(arg0) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'exports1BlsAggregateSignatures',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(1);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var vec1 = arg0;
        var len1 = vec1.length;
        var result1 = realloc0(0, 0, 4, len1 * 8);
        if (result1 < 0 || len1 < 0 || len1 > 33554431 || result1 > memory0.buffer.byteLength || len1 > Math.floor((memory0.buffer.byteLength - result1) / 8)) throw new WebAssemblyRuntimeError('wasm trap: out of bounds memory access');
        for (let i = 0; i < vec1.length; i++) {
          const e = vec1[i];
          const base = result1 + i * 8;var val0 = e;
          var len0 = Array.isArray(val0) ? val0.length : val0.byteLength;
          var ptr0 = realloc0(0, 0, 1, len0 * 1);
          
          let valData0;
          const valLenBytes0 = len0 * 1;
          if (Array.isArray(val0)) {
            // Regular array likely containing numbers, write values to memory
            let offset = 0;
            const dv0 = new DataView(memory0.buffer);
            for (const v of val0) {
              _requireValidNumericPrimitive.bind(null, 'u8')(v);
              dv0.setUint8(ptr0+ offset, v, true);
              offset += 1;
            }
          } else {
            // TypedArray / ArrayBuffer-like, direct copy
            valData0 = new Uint8Array(val0.buffer || val0, val0.byteOffset, valLenBytes0);
            const out0 = new Uint8Array(memory0.buffer, ptr0, valLenBytes0);
            out0.set(valData0);
          }
          
          dataView(memory0).setUint32((base) + 4, len0, true);
          dataView(memory0).setUint32((base) + 0, ptr0, true);
        }
        _debugLog('[iface="bls-aggregate-signatures", function="bls-aggregate-signatures"][Instruction::CallWasm] enter', {
          funcName: 'bls-aggregate-signatures',
          paramCount: 2,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => exports1BlsAggregateSignatures(result1, len1),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant4;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            var ptr2 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true) >>> 0;
            var len2 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true);
            if (ptr2 < 0 || len2 < 0 || len2 > 268435455 || ptr2 > memory0.buffer.byteLength || len2 > Math.floor((memory0.buffer.byteLength - ptr2) / 1)) throw new WebAssemblyRuntimeError('wasm trap: out of bounds memory access');
            if (ptr2 % 1 !== 0) throw new TypeError(`list pointer [${ptr2}] is not aligned to 1`);
            var result2 = new Uint8Array(memory0.buffer.slice(ptr2, ptr2 + len2 * 1));
            variant4= {
              tag: 'ok',
              val: result2
            };
            break;
          }
          case 1: {
            var ptr3 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true) >>> 0;
            var len3 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true);
            var result3 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr3, len3));
            variant4= {
              tag: 'err',
              val: result3
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="bls-aggregate-signatures", function="bls-aggregate-signatures"][Instruction::Return]', {
          funcName: 'bls-aggregate-signatures',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant4;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn0(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let exports1ValidateWit;

function validateWit(arg0) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'exports1ValidateWit',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'none',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(10);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        
        var encodeRes = _utf8AllocateAndEncode(arg0, realloc0, memory0);
        var ptr0= encodeRes.ptr;
        var len0 = encodeRes.len;
        
        _debugLog('[iface="validate-wit", function="validate-wit"][Instruction::CallWasm] enter', {
          funcName: 'validate-wit',
          paramCount: 2,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => exports1ValidateWit(ptr0, len0),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant5;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            variant5= {
              tag: 'ok',
            };
            break;
          }
          case 1: {
            var ptr1 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true) >>> 0;
            var len1 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true);
            var result1 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr1, len1));
            variant5= {
              tag: 'parse-error',
              val: result1
            };
            break;
          }
          case 2: {
            var len4 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true);
            var base4 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true) >>> 0;
            if (base4 < 0 || len4 < 0 || len4 > 16777215 || base4 > memory0.buffer.byteLength || len4 > Math.floor((memory0.buffer.byteLength - base4) / 16)) throw new WebAssemblyRuntimeError('wasm trap: out of bounds memory access');
            if (base4 % 4 !== 0) throw new TypeError(`list pointer [${base4}] is not aligned to 4`);
            var result4 = [];
            for (let i = 0; i < len4; i++) {
              const base = base4 + i * 16;
              var ptr2 = dataView(memory0).getUint32((base) + 0, true) >>> 0;
              var len2 = dataView(memory0).getUint32((base) + 4, true);
              var result2 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr2, len2));
              var ptr3 = dataView(memory0).getUint32((base) + 8, true) >>> 0;
              var len3 = dataView(memory0).getUint32((base) + 12, true);
              var result3 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr3, len3));
              result4.push({
                message: result2,
                location: result3,
              });
            }
            variant5= {
              tag: 'validation-errors',
              val: result4
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for ValidationResult');
          }
        }
        _debugLog('[iface="validate-wit", function="validate-wit"][Instruction::Return]', {
          funcName: 'validate-wit',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        task.resolve([variant5]);
        const retCopy = variant5;
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn2(ret);
        cstate.mayLeave = true;
        task.exit();
        return retCopy;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}

const handleTable0 = [T_FLAG, 0];
handleTable0._createdReps = new Set();
handleTable0._componentIdx = 0;
const finalizationRegistry0 = finalizationRegistryCreate((handle) => {
  const { rep } = rscTableRemove(handleTable0, handle);
  exports0['0'](rep);
});

HANDLE_TABLES[0] = handleTable0;
let witCodecConstructorWit;

class Wit{
  constructor(arg0) {
    
    const hostProvided = false;
    getOrCreateAsyncState(0).throwIfTrapped();
    
    const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
      componentIdx: 0,
      isAsync: false,
      isManualAsync: false,
      preserveFutureResult: false,
      entryFnName: 'witCodecConstructorWit',
      getCallbackFn: () => null,
      callbackFnName: null,
      errHandling: 'none',
      callingWasmExport: true,
    });
    task.setCalleeIsAsync(false);
    task.setFuncTypeIsAsync(false);
    task.setReturnResultTypeIdx(11);
    
    const started = task.enterSync();
    CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
    
    if (0!== null) {
      task.setReturnMemoryIdx(0);
      task.setReturnMemory((() => memory0)());
    }
    
    
    return _withGlobalCurrentTaskMeta({
      taskID: task.id(),
      componentIdx: task.componentIdx(),
      fn: () => {
        try {
          
          
          var encodeRes = _utf8AllocateAndEncode(arg0, realloc0, memory0);
          var ptr0= encodeRes.ptr;
          var len0 = encodeRes.len;
          
          _debugLog('[iface="root:component/wit-codec", function="[constructor]wit"][Instruction::CallWasm] enter', {
            funcName: '[constructor]wit',
            paramCount: 2,
            async: false,
            postReturn: false,
          });
          
          let ret;
          
          try {
            ret =  _withGlobalCurrentTaskMeta({
              taskID: task.id(),
              componentIdx: task.componentIdx(),
              fn: () => witCodecConstructorWit(ptr0, len0),
            });
          } catch (err) {
            
            _debugLog('[Instruction::CallWasm] error during sync call', {
              taskID: task.id(),
              err,
            });
            getOrCreateAsyncState(0).markTrapped(err);
            task.setErrored(err);
            task.reject(err);
            task.exit();
            throw err;
            
          }
          task.endFirstSlice();
          
          var handle2 = ret;
          var rsc1 = new.target === Wit ? this : Object.create(Wit.prototype);
          Object.defineProperty(rsc1, symbolRscHandle, { writable: true, value: handle2});
          finalizationRegistry0.register(rsc1, handle2, rsc1);
          Object.defineProperty(rsc1, symbolDispose, { writable: true, value: function () {
            finalizationRegistry0.unregister(rsc1);
            const handleEntry = rscTableRemove(handleTable0, handle2);
            rsc1[symbolDispose] = emptyFunc;
            rsc1[symbolRscHandle] = undefined;
            exports0['0'](handleEntry.rep);
          }});
          _debugLog('[iface="root:component/wit-codec", function="[constructor]wit"][Instruction::Return]', {
            funcName: '[constructor]wit',
            paramCount: 1,
            async: false,
            postReturn: false
          });
          task.resolve([rsc1]);
          task.exit();
          return rsc1;
          
        } catch (err) {
          if (!task.isResolvedState()) {
            task.setErrored(err);
            task.reject(err);
          }
          if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
          throw err;
        }
      },
    });
    
  }
}
let witCodecMethodWitEncodeCall;

Wit.prototype.encodeCall = function encodeCall(arg1, arg2) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'witCodecMethodWitEncodeCall',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(3);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        
        var handle1 = this[symbolRscHandle];
        if (!handle1 || (handleTable0[(handle1 << 1) + 1] & T_FLAG) === 0) {
          throw new TypeError('Resource error: Not a valid \"Wit\" resource.');
        }
        var handle0 = handleTable0[(handle1 << 1) + 1] & ~T_FLAG;
        
        
        var encodeRes = _utf8AllocateAndEncode(arg1, realloc0, memory0);
        var ptr2= encodeRes.ptr;
        var len2 = encodeRes.len;
        
        
        var encodeRes = _utf8AllocateAndEncode(arg2, realloc0, memory0);
        var ptr3= encodeRes.ptr;
        var len3 = encodeRes.len;
        
        _debugLog('[iface="root:component/wit-codec", function="[method]wit.encode-call"][Instruction::CallWasm] enter', {
          funcName: '[method]wit.encode-call',
          paramCount: 5,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => witCodecMethodWitEncodeCall(handle0, ptr2, len2, ptr3, len3),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant6;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            var ptr4 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true) >>> 0;
            var len4 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true);
            var result4 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr4, len4));
            variant6= {
              tag: 'ok',
              val: result4
            };
            break;
          }
          case 1: {
            var ptr5 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true) >>> 0;
            var len5 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true);
            var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
            variant6= {
              tag: 'err',
              val: result5
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="root:component/wit-codec", function="[method]wit.encode-call"][Instruction::Return]', {
          funcName: '[method]wit.encode-call',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant6;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn0(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
};
let witCodecMethodWitDecodeResult;

Wit.prototype.decodeResult = function decodeResult(arg1, arg2) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'witCodecMethodWitDecodeResult',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(3);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        
        var handle1 = this[symbolRscHandle];
        if (!handle1 || (handleTable0[(handle1 << 1) + 1] & T_FLAG) === 0) {
          throw new TypeError('Resource error: Not a valid \"Wit\" resource.');
        }
        var handle0 = handleTable0[(handle1 << 1) + 1] & ~T_FLAG;
        
        
        var encodeRes = _utf8AllocateAndEncode(arg1, realloc0, memory0);
        var ptr2= encodeRes.ptr;
        var len2 = encodeRes.len;
        
        
        var encodeRes = _utf8AllocateAndEncode(arg2, realloc0, memory0);
        var ptr3= encodeRes.ptr;
        var len3 = encodeRes.len;
        
        _debugLog('[iface="root:component/wit-codec", function="[method]wit.decode-result"][Instruction::CallWasm] enter', {
          funcName: '[method]wit.decode-result',
          paramCount: 5,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => witCodecMethodWitDecodeResult(handle0, ptr2, len2, ptr3, len3),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant6;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            var ptr4 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true) >>> 0;
            var len4 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true);
            var result4 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr4, len4));
            variant6= {
              tag: 'ok',
              val: result4
            };
            break;
          }
          case 1: {
            var ptr5 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true) >>> 0;
            var len5 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true);
            var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
            variant6= {
              tag: 'err',
              val: result5
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="root:component/wit-codec", function="[method]wit.decode-result"][Instruction::Return]', {
          funcName: '[method]wit.decode-result',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant6;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn0(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
};
let witCodecMethodWitParse;

Wit.prototype.parse = function parse() {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'witCodecMethodWitParse',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(3);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        
        var handle1 = this[symbolRscHandle];
        if (!handle1 || (handleTable0[(handle1 << 1) + 1] & T_FLAG) === 0) {
          throw new TypeError('Resource error: Not a valid \"Wit\" resource.');
        }
        var handle0 = handleTable0[(handle1 << 1) + 1] & ~T_FLAG;
        
        _debugLog('[iface="root:component/wit-codec", function="[method]wit.parse"][Instruction::CallWasm] enter', {
          funcName: '[method]wit.parse',
          paramCount: 1,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => witCodecMethodWitParse(handle0),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant4;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            var ptr2 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true) >>> 0;
            var len2 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true);
            var result2 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr2, len2));
            variant4= {
              tag: 'ok',
              val: result2
            };
            break;
          }
          case 1: {
            var ptr3 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true) >>> 0;
            var len3 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true);
            var result3 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr3, len3));
            variant4= {
              tag: 'err',
              val: result3
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="root:component/wit-codec", function="[method]wit.parse"][Instruction::Return]', {
          funcName: '[method]wit.parse',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant4;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn0(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
};
let numericsU64ToInteger;

function u64ToInteger(arg0) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsU64ToInteger',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'none',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(15);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        _debugLog('[iface="root:component/numerics", function="u64-to-integer"][Instruction::CallWasm] enter', {
          funcName: 'u64-to-integer',
          paramCount: 1,
          async: false,
          postReturn: false,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsU64ToInteger(toUint64(arg0)),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let enum0;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 32, true)) {
          case 0: {
            enum0 = 'plus';
            break;
          }
          case 1: {
            enum0 = 'minus';
            break;
          }
          default: {
            throw new TypeError('invalid discriminant specified for Sign');
          }
        }
        _debugLog('[iface="root:component/numerics", function="u64-to-integer"][Instruction::Return]', {
          funcName: 'u64-to-integer',
          paramCount: 1,
          async: false,
          postReturn: false
        });
        task.resolve([{
          r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 0, true))),
          r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 8, true))),
          r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 16, true))),
          r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 24, true))),
          sign: enum0,
        }]);
        task.exit();
        return {
          r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 0, true))),
          r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 8, true))),
          r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 16, true))),
          r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 24, true))),
          sign: enum0,
        };
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let numericsS64ToInteger;

function s64ToInteger(arg0) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsS64ToInteger',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'none',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(15);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        _debugLog('[iface="root:component/numerics", function="s64-to-integer"][Instruction::CallWasm] enter', {
          funcName: 's64-to-integer',
          paramCount: 1,
          async: false,
          postReturn: false,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsS64ToInteger(toInt64(arg0)),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let enum0;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 32, true)) {
          case 0: {
            enum0 = 'plus';
            break;
          }
          case 1: {
            enum0 = 'minus';
            break;
          }
          default: {
            throw new TypeError('invalid discriminant specified for Sign');
          }
        }
        _debugLog('[iface="root:component/numerics", function="s64-to-integer"][Instruction::Return]', {
          funcName: 's64-to-integer',
          paramCount: 1,
          async: false,
          postReturn: false
        });
        task.resolve([{
          r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 0, true))),
          r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 8, true))),
          r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 16, true))),
          r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 24, true))),
          sign: enum0,
        }]);
        task.exit();
        return {
          r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 0, true))),
          r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 8, true))),
          r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 16, true))),
          r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 24, true))),
          sign: enum0,
        };
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let numericsStringToInteger;

function stringToInteger(arg0) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsStringToInteger',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(17);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        
        var encodeRes = _utf8AllocateAndEncode(arg0, realloc0, memory0);
        var ptr0= encodeRes.ptr;
        var len0 = encodeRes.len;
        
        _debugLog('[iface="root:component/numerics", function="string-to-integer"][Instruction::CallWasm] enter', {
          funcName: 'string-to-integer',
          paramCount: 2,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsStringToInteger(ptr0, len0),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant8;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            let enum1;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 40, true)) {
              case 0: {
                enum1 = 'plus';
                break;
              }
              case 1: {
                enum1 = 'minus';
                break;
              }
              default: {
                throw new TypeError('invalid discriminant specified for Sign');
              }
            }
            variant8= {
              tag: 'ok',
              val: {
                r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 8, true))),
                r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 16, true))),
                r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 24, true))),
                r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 32, true))),
                sign: enum1,
              }
            };
            break;
          }
          case 1: {
            let variant7;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 8, true)) {
              case 0: {
                var ptr2 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len2 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result2 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr2, len2));
                variant7= {
                  tag: 'message',
                  val: result2
                };
                break;
              }
              case 1: {
                var ptr3 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len3 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result3 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr3, len3));
                variant7= {
                  tag: 'overflow',
                  val: result3
                };
                break;
              }
              case 2: {
                var ptr4 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len4 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result4 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr4, len4));
                variant7= {
                  tag: 'div-by-zero',
                  val: result4
                };
                break;
              }
              case 3: {
                var ptr5 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len5 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
                variant7= {
                  tag: 'syntax',
                  val: result5
                };
                break;
              }
              case 4: {
                var ptr6 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len6 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
                variant7= {
                  tag: 'validation',
                  val: result6
                };
                break;
              }
              default: {
                throw new TypeError('invalid variant discriminant for NumericsError');
              }
            }
            variant8= {
              tag: 'err',
              val: variant7
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="root:component/numerics", function="string-to-integer"][Instruction::Return]', {
          funcName: 'string-to-integer',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant8;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn3(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let numericsIntegerToString;

function integerToString(arg0) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsIntegerToString',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'none',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(0);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var {r0: v0_0, r1: v0_1, r2: v0_2, r3: v0_3, sign: v0_4 } = arg0;
        var val1 = v0_4;
        let enum1;
        switch (val1) {
          case 'plus': {
            enum1 = 0;
            break;
          }
          case 'minus': {
            enum1 = 1;
            break;
          }
          default: {
            if ((v0_4) instanceof Error) {
              console.error(v0_4);
            }
            
            throw new TypeError(`"${val1}" is not one of the cases of sign`);
          }
        }
        _debugLog('[iface="root:component/numerics", function="integer-to-string"][Instruction::CallWasm] enter', {
          funcName: 'integer-to-string',
          paramCount: 5,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsIntegerToString(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        var ptr2 = dataView(memory0).getUint32(((ret >>> 0)) + 0, true) >>> 0;
        var len2 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true);
        var result2 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr2, len2));
        _debugLog('[iface="root:component/numerics", function="integer-to-string"][Instruction::Return]', {
          funcName: 'integer-to-string',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        task.resolve([result2]);
        const retCopy = result2;
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn4(ret);
        cstate.mayLeave = true;
        task.exit();
        return retCopy;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let numericsEqInteger;

function eqInteger(arg0, arg1) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsEqInteger',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'none',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(19);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (null!== null) {
    task.setReturnMemoryIdx(null);
    task.setReturnMemory((() => null)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var {r0: v0_0, r1: v0_1, r2: v0_2, r3: v0_3, sign: v0_4 } = arg0;
        var val1 = v0_4;
        let enum1;
        switch (val1) {
          case 'plus': {
            enum1 = 0;
            break;
          }
          case 'minus': {
            enum1 = 1;
            break;
          }
          default: {
            if ((v0_4) instanceof Error) {
              console.error(v0_4);
            }
            
            throw new TypeError(`"${val1}" is not one of the cases of sign`);
          }
        }
        var {r0: v2_0, r1: v2_1, r2: v2_2, r3: v2_3, sign: v2_4 } = arg1;
        var val3 = v2_4;
        let enum3;
        switch (val3) {
          case 'plus': {
            enum3 = 0;
            break;
          }
          case 'minus': {
            enum3 = 1;
            break;
          }
          default: {
            if ((v2_4) instanceof Error) {
              console.error(v2_4);
            }
            
            throw new TypeError(`"${val3}" is not one of the cases of sign`);
          }
        }
        _debugLog('[iface="root:component/numerics", function="eq-integer"][Instruction::CallWasm] enter', {
          funcName: 'eq-integer',
          paramCount: 10,
          async: false,
          postReturn: false,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsEqInteger(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1, toUint64(v2_0), toUint64(v2_1), toUint64(v2_2), toUint64(v2_3), enum3),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        var bool4 = ret;
        _debugLog('[iface="root:component/numerics", function="eq-integer"][Instruction::Return]', {
          funcName: 'eq-integer',
          paramCount: 1,
          async: false,
          postReturn: false
        });
        task.resolve([bool4 == 0 ? false : (bool4 == 1 ? true : throwInvalidBool())]);
        task.exit();
        return bool4 == 0 ? false : (bool4 == 1 ? true : throwInvalidBool());
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let numericsCmpInteger;

function cmpInteger(arg0, arg1) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsCmpInteger',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'none',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(20);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (null!== null) {
    task.setReturnMemoryIdx(null);
    task.setReturnMemory((() => null)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var {r0: v0_0, r1: v0_1, r2: v0_2, r3: v0_3, sign: v0_4 } = arg0;
        var val1 = v0_4;
        let enum1;
        switch (val1) {
          case 'plus': {
            enum1 = 0;
            break;
          }
          case 'minus': {
            enum1 = 1;
            break;
          }
          default: {
            if ((v0_4) instanceof Error) {
              console.error(v0_4);
            }
            
            throw new TypeError(`"${val1}" is not one of the cases of sign`);
          }
        }
        var {r0: v2_0, r1: v2_1, r2: v2_2, r3: v2_3, sign: v2_4 } = arg1;
        var val3 = v2_4;
        let enum3;
        switch (val3) {
          case 'plus': {
            enum3 = 0;
            break;
          }
          case 'minus': {
            enum3 = 1;
            break;
          }
          default: {
            if ((v2_4) instanceof Error) {
              console.error(v2_4);
            }
            
            throw new TypeError(`"${val3}" is not one of the cases of sign`);
          }
        }
        _debugLog('[iface="root:component/numerics", function="cmp-integer"][Instruction::CallWasm] enter', {
          funcName: 'cmp-integer',
          paramCount: 10,
          async: false,
          postReturn: false,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsCmpInteger(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1, toUint64(v2_0), toUint64(v2_1), toUint64(v2_2), toUint64(v2_3), enum3),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let enum4;
        switch (ret) {
          case 0: {
            enum4 = 'less';
            break;
          }
          case 1: {
            enum4 = 'equal';
            break;
          }
          case 2: {
            enum4 = 'greater';
            break;
          }
          default: {
            throw new TypeError('invalid discriminant specified for Ordering');
          }
        }
        _debugLog('[iface="root:component/numerics", function="cmp-integer"][Instruction::Return]', {
          funcName: 'cmp-integer',
          paramCount: 1,
          async: false,
          postReturn: false
        });
        task.resolve([enum4]);
        task.exit();
        return enum4;
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let numericsAddInteger;

function addInteger(arg0, arg1) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsAddInteger',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(17);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var {r0: v0_0, r1: v0_1, r2: v0_2, r3: v0_3, sign: v0_4 } = arg0;
        var val1 = v0_4;
        let enum1;
        switch (val1) {
          case 'plus': {
            enum1 = 0;
            break;
          }
          case 'minus': {
            enum1 = 1;
            break;
          }
          default: {
            if ((v0_4) instanceof Error) {
              console.error(v0_4);
            }
            
            throw new TypeError(`"${val1}" is not one of the cases of sign`);
          }
        }
        var {r0: v2_0, r1: v2_1, r2: v2_2, r3: v2_3, sign: v2_4 } = arg1;
        var val3 = v2_4;
        let enum3;
        switch (val3) {
          case 'plus': {
            enum3 = 0;
            break;
          }
          case 'minus': {
            enum3 = 1;
            break;
          }
          default: {
            if ((v2_4) instanceof Error) {
              console.error(v2_4);
            }
            
            throw new TypeError(`"${val3}" is not one of the cases of sign`);
          }
        }
        _debugLog('[iface="root:component/numerics", function="add-integer"][Instruction::CallWasm] enter', {
          funcName: 'add-integer',
          paramCount: 10,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsAddInteger(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1, toUint64(v2_0), toUint64(v2_1), toUint64(v2_2), toUint64(v2_3), enum3),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant11;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            let enum4;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 40, true)) {
              case 0: {
                enum4 = 'plus';
                break;
              }
              case 1: {
                enum4 = 'minus';
                break;
              }
              default: {
                throw new TypeError('invalid discriminant specified for Sign');
              }
            }
            variant11= {
              tag: 'ok',
              val: {
                r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 8, true))),
                r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 16, true))),
                r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 24, true))),
                r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 32, true))),
                sign: enum4,
              }
            };
            break;
          }
          case 1: {
            let variant10;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 8, true)) {
              case 0: {
                var ptr5 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len5 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
                variant10= {
                  tag: 'message',
                  val: result5
                };
                break;
              }
              case 1: {
                var ptr6 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len6 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
                variant10= {
                  tag: 'overflow',
                  val: result6
                };
                break;
              }
              case 2: {
                var ptr7 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len7 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result7 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr7, len7));
                variant10= {
                  tag: 'div-by-zero',
                  val: result7
                };
                break;
              }
              case 3: {
                var ptr8 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len8 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result8 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr8, len8));
                variant10= {
                  tag: 'syntax',
                  val: result8
                };
                break;
              }
              case 4: {
                var ptr9 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len9 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result9 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr9, len9));
                variant10= {
                  tag: 'validation',
                  val: result9
                };
                break;
              }
              default: {
                throw new TypeError('invalid variant discriminant for NumericsError');
              }
            }
            variant11= {
              tag: 'err',
              val: variant10
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="root:component/numerics", function="add-integer"][Instruction::Return]', {
          funcName: 'add-integer',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant11;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn3(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let numericsSubInteger;

function subInteger(arg0, arg1) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsSubInteger',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(17);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var {r0: v0_0, r1: v0_1, r2: v0_2, r3: v0_3, sign: v0_4 } = arg0;
        var val1 = v0_4;
        let enum1;
        switch (val1) {
          case 'plus': {
            enum1 = 0;
            break;
          }
          case 'minus': {
            enum1 = 1;
            break;
          }
          default: {
            if ((v0_4) instanceof Error) {
              console.error(v0_4);
            }
            
            throw new TypeError(`"${val1}" is not one of the cases of sign`);
          }
        }
        var {r0: v2_0, r1: v2_1, r2: v2_2, r3: v2_3, sign: v2_4 } = arg1;
        var val3 = v2_4;
        let enum3;
        switch (val3) {
          case 'plus': {
            enum3 = 0;
            break;
          }
          case 'minus': {
            enum3 = 1;
            break;
          }
          default: {
            if ((v2_4) instanceof Error) {
              console.error(v2_4);
            }
            
            throw new TypeError(`"${val3}" is not one of the cases of sign`);
          }
        }
        _debugLog('[iface="root:component/numerics", function="sub-integer"][Instruction::CallWasm] enter', {
          funcName: 'sub-integer',
          paramCount: 10,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsSubInteger(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1, toUint64(v2_0), toUint64(v2_1), toUint64(v2_2), toUint64(v2_3), enum3),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant11;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            let enum4;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 40, true)) {
              case 0: {
                enum4 = 'plus';
                break;
              }
              case 1: {
                enum4 = 'minus';
                break;
              }
              default: {
                throw new TypeError('invalid discriminant specified for Sign');
              }
            }
            variant11= {
              tag: 'ok',
              val: {
                r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 8, true))),
                r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 16, true))),
                r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 24, true))),
                r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 32, true))),
                sign: enum4,
              }
            };
            break;
          }
          case 1: {
            let variant10;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 8, true)) {
              case 0: {
                var ptr5 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len5 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
                variant10= {
                  tag: 'message',
                  val: result5
                };
                break;
              }
              case 1: {
                var ptr6 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len6 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
                variant10= {
                  tag: 'overflow',
                  val: result6
                };
                break;
              }
              case 2: {
                var ptr7 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len7 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result7 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr7, len7));
                variant10= {
                  tag: 'div-by-zero',
                  val: result7
                };
                break;
              }
              case 3: {
                var ptr8 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len8 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result8 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr8, len8));
                variant10= {
                  tag: 'syntax',
                  val: result8
                };
                break;
              }
              case 4: {
                var ptr9 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len9 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result9 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr9, len9));
                variant10= {
                  tag: 'validation',
                  val: result9
                };
                break;
              }
              default: {
                throw new TypeError('invalid variant discriminant for NumericsError');
              }
            }
            variant11= {
              tag: 'err',
              val: variant10
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="root:component/numerics", function="sub-integer"][Instruction::Return]', {
          funcName: 'sub-integer',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant11;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn3(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let numericsMulInteger;

function mulInteger(arg0, arg1) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsMulInteger',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(17);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var {r0: v0_0, r1: v0_1, r2: v0_2, r3: v0_3, sign: v0_4 } = arg0;
        var val1 = v0_4;
        let enum1;
        switch (val1) {
          case 'plus': {
            enum1 = 0;
            break;
          }
          case 'minus': {
            enum1 = 1;
            break;
          }
          default: {
            if ((v0_4) instanceof Error) {
              console.error(v0_4);
            }
            
            throw new TypeError(`"${val1}" is not one of the cases of sign`);
          }
        }
        var {r0: v2_0, r1: v2_1, r2: v2_2, r3: v2_3, sign: v2_4 } = arg1;
        var val3 = v2_4;
        let enum3;
        switch (val3) {
          case 'plus': {
            enum3 = 0;
            break;
          }
          case 'minus': {
            enum3 = 1;
            break;
          }
          default: {
            if ((v2_4) instanceof Error) {
              console.error(v2_4);
            }
            
            throw new TypeError(`"${val3}" is not one of the cases of sign`);
          }
        }
        _debugLog('[iface="root:component/numerics", function="mul-integer"][Instruction::CallWasm] enter', {
          funcName: 'mul-integer',
          paramCount: 10,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsMulInteger(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1, toUint64(v2_0), toUint64(v2_1), toUint64(v2_2), toUint64(v2_3), enum3),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant11;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            let enum4;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 40, true)) {
              case 0: {
                enum4 = 'plus';
                break;
              }
              case 1: {
                enum4 = 'minus';
                break;
              }
              default: {
                throw new TypeError('invalid discriminant specified for Sign');
              }
            }
            variant11= {
              tag: 'ok',
              val: {
                r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 8, true))),
                r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 16, true))),
                r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 24, true))),
                r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 32, true))),
                sign: enum4,
              }
            };
            break;
          }
          case 1: {
            let variant10;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 8, true)) {
              case 0: {
                var ptr5 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len5 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
                variant10= {
                  tag: 'message',
                  val: result5
                };
                break;
              }
              case 1: {
                var ptr6 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len6 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
                variant10= {
                  tag: 'overflow',
                  val: result6
                };
                break;
              }
              case 2: {
                var ptr7 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len7 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result7 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr7, len7));
                variant10= {
                  tag: 'div-by-zero',
                  val: result7
                };
                break;
              }
              case 3: {
                var ptr8 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len8 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result8 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr8, len8));
                variant10= {
                  tag: 'syntax',
                  val: result8
                };
                break;
              }
              case 4: {
                var ptr9 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len9 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result9 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr9, len9));
                variant10= {
                  tag: 'validation',
                  val: result9
                };
                break;
              }
              default: {
                throw new TypeError('invalid variant discriminant for NumericsError');
              }
            }
            variant11= {
              tag: 'err',
              val: variant10
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="root:component/numerics", function="mul-integer"][Instruction::Return]', {
          funcName: 'mul-integer',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant11;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn3(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let numericsDivInteger;

function divInteger(arg0, arg1) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsDivInteger',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(17);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var {r0: v0_0, r1: v0_1, r2: v0_2, r3: v0_3, sign: v0_4 } = arg0;
        var val1 = v0_4;
        let enum1;
        switch (val1) {
          case 'plus': {
            enum1 = 0;
            break;
          }
          case 'minus': {
            enum1 = 1;
            break;
          }
          default: {
            if ((v0_4) instanceof Error) {
              console.error(v0_4);
            }
            
            throw new TypeError(`"${val1}" is not one of the cases of sign`);
          }
        }
        var {r0: v2_0, r1: v2_1, r2: v2_2, r3: v2_3, sign: v2_4 } = arg1;
        var val3 = v2_4;
        let enum3;
        switch (val3) {
          case 'plus': {
            enum3 = 0;
            break;
          }
          case 'minus': {
            enum3 = 1;
            break;
          }
          default: {
            if ((v2_4) instanceof Error) {
              console.error(v2_4);
            }
            
            throw new TypeError(`"${val3}" is not one of the cases of sign`);
          }
        }
        _debugLog('[iface="root:component/numerics", function="div-integer"][Instruction::CallWasm] enter', {
          funcName: 'div-integer',
          paramCount: 10,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsDivInteger(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1, toUint64(v2_0), toUint64(v2_1), toUint64(v2_2), toUint64(v2_3), enum3),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant11;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            let enum4;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 40, true)) {
              case 0: {
                enum4 = 'plus';
                break;
              }
              case 1: {
                enum4 = 'minus';
                break;
              }
              default: {
                throw new TypeError('invalid discriminant specified for Sign');
              }
            }
            variant11= {
              tag: 'ok',
              val: {
                r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 8, true))),
                r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 16, true))),
                r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 24, true))),
                r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 32, true))),
                sign: enum4,
              }
            };
            break;
          }
          case 1: {
            let variant10;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 8, true)) {
              case 0: {
                var ptr5 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len5 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
                variant10= {
                  tag: 'message',
                  val: result5
                };
                break;
              }
              case 1: {
                var ptr6 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len6 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
                variant10= {
                  tag: 'overflow',
                  val: result6
                };
                break;
              }
              case 2: {
                var ptr7 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len7 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result7 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr7, len7));
                variant10= {
                  tag: 'div-by-zero',
                  val: result7
                };
                break;
              }
              case 3: {
                var ptr8 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len8 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result8 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr8, len8));
                variant10= {
                  tag: 'syntax',
                  val: result8
                };
                break;
              }
              case 4: {
                var ptr9 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len9 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result9 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr9, len9));
                variant10= {
                  tag: 'validation',
                  val: result9
                };
                break;
              }
              default: {
                throw new TypeError('invalid variant discriminant for NumericsError');
              }
            }
            variant11= {
              tag: 'err',
              val: variant10
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="root:component/numerics", function="div-integer"][Instruction::Return]', {
          funcName: 'div-integer',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant11;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn3(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let numericsMulAddDivRemInteger;

function mulAddDivRemInteger(arg0, arg1, arg2, arg3) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsMulAddDivRemInteger',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(22);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var ptr0 = realloc0(0, 0, 8, 160);
        var {r0: v1_0, r1: v1_1, r2: v1_2, r3: v1_3, sign: v1_4 } = arg0;
        dataView(memory0).setBigInt64((ptr0) + 0, toUint64(v1_0), true);
        dataView(memory0).setBigInt64((ptr0) + 8, toUint64(v1_1), true);
        dataView(memory0).setBigInt64((ptr0) + 16, toUint64(v1_2), true);
        dataView(memory0).setBigInt64((ptr0) + 24, toUint64(v1_3), true);
        var val2 = v1_4;
        let enum2;
        switch (val2) {
          case 'plus': {
            enum2 = 0;
            break;
          }
          case 'minus': {
            enum2 = 1;
            break;
          }
          default: {
            if ((v1_4) instanceof Error) {
              console.error(v1_4);
            }
            
            throw new TypeError(`"${val2}" is not one of the cases of sign`);
          }
        }
        dataView(memory0).setInt8((ptr0) + 32, enum2, true);
        var {r0: v3_0, r1: v3_1, r2: v3_2, r3: v3_3, sign: v3_4 } = arg1;
        dataView(memory0).setBigInt64((ptr0) + 40, toUint64(v3_0), true);
        dataView(memory0).setBigInt64((ptr0) + 48, toUint64(v3_1), true);
        dataView(memory0).setBigInt64((ptr0) + 56, toUint64(v3_2), true);
        dataView(memory0).setBigInt64((ptr0) + 64, toUint64(v3_3), true);
        var val4 = v3_4;
        let enum4;
        switch (val4) {
          case 'plus': {
            enum4 = 0;
            break;
          }
          case 'minus': {
            enum4 = 1;
            break;
          }
          default: {
            if ((v3_4) instanceof Error) {
              console.error(v3_4);
            }
            
            throw new TypeError(`"${val4}" is not one of the cases of sign`);
          }
        }
        dataView(memory0).setInt8((ptr0) + 72, enum4, true);
        var {r0: v5_0, r1: v5_1, r2: v5_2, r3: v5_3, sign: v5_4 } = arg2;
        dataView(memory0).setBigInt64((ptr0) + 80, toUint64(v5_0), true);
        dataView(memory0).setBigInt64((ptr0) + 88, toUint64(v5_1), true);
        dataView(memory0).setBigInt64((ptr0) + 96, toUint64(v5_2), true);
        dataView(memory0).setBigInt64((ptr0) + 104, toUint64(v5_3), true);
        var val6 = v5_4;
        let enum6;
        switch (val6) {
          case 'plus': {
            enum6 = 0;
            break;
          }
          case 'minus': {
            enum6 = 1;
            break;
          }
          default: {
            if ((v5_4) instanceof Error) {
              console.error(v5_4);
            }
            
            throw new TypeError(`"${val6}" is not one of the cases of sign`);
          }
        }
        dataView(memory0).setInt8((ptr0) + 112, enum6, true);
        var {r0: v7_0, r1: v7_1, r2: v7_2, r3: v7_3, sign: v7_4 } = arg3;
        dataView(memory0).setBigInt64((ptr0) + 120, toUint64(v7_0), true);
        dataView(memory0).setBigInt64((ptr0) + 128, toUint64(v7_1), true);
        dataView(memory0).setBigInt64((ptr0) + 136, toUint64(v7_2), true);
        dataView(memory0).setBigInt64((ptr0) + 144, toUint64(v7_3), true);
        var val8 = v7_4;
        let enum8;
        switch (val8) {
          case 'plus': {
            enum8 = 0;
            break;
          }
          case 'minus': {
            enum8 = 1;
            break;
          }
          default: {
            if ((v7_4) instanceof Error) {
              console.error(v7_4);
            }
            
            throw new TypeError(`"${val8}" is not one of the cases of sign`);
          }
        }
        dataView(memory0).setInt8((ptr0) + 152, enum8, true);
        _debugLog('[iface="root:component/numerics", function="mul-add-div-rem-integer"][Instruction::CallWasm] enter', {
          funcName: 'mul-add-div-rem-integer',
          paramCount: 1,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsMulAddDivRemInteger(ptr0),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant17;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            let enum9;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 40, true)) {
              case 0: {
                enum9 = 'plus';
                break;
              }
              case 1: {
                enum9 = 'minus';
                break;
              }
              default: {
                throw new TypeError('invalid discriminant specified for Sign');
              }
            }
            let enum10;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 80, true)) {
              case 0: {
                enum10 = 'plus';
                break;
              }
              case 1: {
                enum10 = 'minus';
                break;
              }
              default: {
                throw new TypeError('invalid discriminant specified for Sign');
              }
            }
            variant17= {
              tag: 'ok',
              val: [{
                r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 8, true))),
                r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 16, true))),
                r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 24, true))),
                r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 32, true))),
                sign: enum9,
              }, {
                r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 48, true))),
                r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 56, true))),
                r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 64, true))),
                r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 72, true))),
                sign: enum10,
              }]
            };
            break;
          }
          case 1: {
            let variant16;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 8, true)) {
              case 0: {
                var ptr11 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len11 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result11 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr11, len11));
                variant16= {
                  tag: 'message',
                  val: result11
                };
                break;
              }
              case 1: {
                var ptr12 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len12 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result12 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr12, len12));
                variant16= {
                  tag: 'overflow',
                  val: result12
                };
                break;
              }
              case 2: {
                var ptr13 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len13 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result13 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr13, len13));
                variant16= {
                  tag: 'div-by-zero',
                  val: result13
                };
                break;
              }
              case 3: {
                var ptr14 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len14 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result14 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr14, len14));
                variant16= {
                  tag: 'syntax',
                  val: result14
                };
                break;
              }
              case 4: {
                var ptr15 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len15 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result15 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr15, len15));
                variant16= {
                  tag: 'validation',
                  val: result15
                };
                break;
              }
              default: {
                throw new TypeError('invalid variant discriminant for NumericsError');
              }
            }
            variant17= {
              tag: 'err',
              val: variant16
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="root:component/numerics", function="mul-add-div-rem-integer"][Instruction::Return]', {
          funcName: 'mul-add-div-rem-integer',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant17;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn3(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let numericsSqrtInteger;

function sqrtInteger(arg0) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsSqrtInteger',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(17);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var {r0: v0_0, r1: v0_1, r2: v0_2, r3: v0_3, sign: v0_4 } = arg0;
        var val1 = v0_4;
        let enum1;
        switch (val1) {
          case 'plus': {
            enum1 = 0;
            break;
          }
          case 'minus': {
            enum1 = 1;
            break;
          }
          default: {
            if ((v0_4) instanceof Error) {
              console.error(v0_4);
            }
            
            throw new TypeError(`"${val1}" is not one of the cases of sign`);
          }
        }
        _debugLog('[iface="root:component/numerics", function="sqrt-integer"][Instruction::CallWasm] enter', {
          funcName: 'sqrt-integer',
          paramCount: 5,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsSqrtInteger(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant9;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            let enum2;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 40, true)) {
              case 0: {
                enum2 = 'plus';
                break;
              }
              case 1: {
                enum2 = 'minus';
                break;
              }
              default: {
                throw new TypeError('invalid discriminant specified for Sign');
              }
            }
            variant9= {
              tag: 'ok',
              val: {
                r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 8, true))),
                r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 16, true))),
                r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 24, true))),
                r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 32, true))),
                sign: enum2,
              }
            };
            break;
          }
          case 1: {
            let variant8;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 8, true)) {
              case 0: {
                var ptr3 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len3 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result3 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr3, len3));
                variant8= {
                  tag: 'message',
                  val: result3
                };
                break;
              }
              case 1: {
                var ptr4 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len4 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result4 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr4, len4));
                variant8= {
                  tag: 'overflow',
                  val: result4
                };
                break;
              }
              case 2: {
                var ptr5 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len5 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
                variant8= {
                  tag: 'div-by-zero',
                  val: result5
                };
                break;
              }
              case 3: {
                var ptr6 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len6 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
                variant8= {
                  tag: 'syntax',
                  val: result6
                };
                break;
              }
              case 4: {
                var ptr7 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len7 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result7 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr7, len7));
                variant8= {
                  tag: 'validation',
                  val: result7
                };
                break;
              }
              default: {
                throw new TypeError('invalid variant discriminant for NumericsError');
              }
            }
            variant9= {
              tag: 'err',
              val: variant8
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="root:component/numerics", function="sqrt-integer"][Instruction::Return]', {
          funcName: 'sqrt-integer',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant9;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn3(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let numericsIntegerToDecimal;

function integerToDecimal(arg0) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsIntegerToDecimal',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(17);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var {r0: v0_0, r1: v0_1, r2: v0_2, r3: v0_3, sign: v0_4 } = arg0;
        var val1 = v0_4;
        let enum1;
        switch (val1) {
          case 'plus': {
            enum1 = 0;
            break;
          }
          case 'minus': {
            enum1 = 1;
            break;
          }
          default: {
            if ((v0_4) instanceof Error) {
              console.error(v0_4);
            }
            
            throw new TypeError(`"${val1}" is not one of the cases of sign`);
          }
        }
        _debugLog('[iface="root:component/numerics", function="integer-to-decimal"][Instruction::CallWasm] enter', {
          funcName: 'integer-to-decimal',
          paramCount: 5,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsIntegerToDecimal(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant9;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            let enum2;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 40, true)) {
              case 0: {
                enum2 = 'plus';
                break;
              }
              case 1: {
                enum2 = 'minus';
                break;
              }
              default: {
                throw new TypeError('invalid discriminant specified for Sign');
              }
            }
            variant9= {
              tag: 'ok',
              val: {
                r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 8, true))),
                r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 16, true))),
                r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 24, true))),
                r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 32, true))),
                sign: enum2,
              }
            };
            break;
          }
          case 1: {
            let variant8;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 8, true)) {
              case 0: {
                var ptr3 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len3 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result3 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr3, len3));
                variant8= {
                  tag: 'message',
                  val: result3
                };
                break;
              }
              case 1: {
                var ptr4 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len4 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result4 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr4, len4));
                variant8= {
                  tag: 'overflow',
                  val: result4
                };
                break;
              }
              case 2: {
                var ptr5 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len5 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
                variant8= {
                  tag: 'div-by-zero',
                  val: result5
                };
                break;
              }
              case 3: {
                var ptr6 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len6 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
                variant8= {
                  tag: 'syntax',
                  val: result6
                };
                break;
              }
              case 4: {
                var ptr7 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len7 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result7 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr7, len7));
                variant8= {
                  tag: 'validation',
                  val: result7
                };
                break;
              }
              default: {
                throw new TypeError('invalid variant discriminant for NumericsError');
              }
            }
            variant9= {
              tag: 'err',
              val: variant8
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="root:component/numerics", function="integer-to-decimal"][Instruction::Return]', {
          funcName: 'integer-to-decimal',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant9;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn3(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let numericsDecimalToInteger;

function decimalToInteger(arg0) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsDecimalToInteger',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(17);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var {r0: v0_0, r1: v0_1, r2: v0_2, r3: v0_3, sign: v0_4 } = arg0;
        var val1 = v0_4;
        let enum1;
        switch (val1) {
          case 'plus': {
            enum1 = 0;
            break;
          }
          case 'minus': {
            enum1 = 1;
            break;
          }
          default: {
            if ((v0_4) instanceof Error) {
              console.error(v0_4);
            }
            
            throw new TypeError(`"${val1}" is not one of the cases of sign`);
          }
        }
        _debugLog('[iface="root:component/numerics", function="decimal-to-integer"][Instruction::CallWasm] enter', {
          funcName: 'decimal-to-integer',
          paramCount: 5,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsDecimalToInteger(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant9;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            let enum2;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 40, true)) {
              case 0: {
                enum2 = 'plus';
                break;
              }
              case 1: {
                enum2 = 'minus';
                break;
              }
              default: {
                throw new TypeError('invalid discriminant specified for Sign');
              }
            }
            variant9= {
              tag: 'ok',
              val: {
                r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 8, true))),
                r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 16, true))),
                r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 24, true))),
                r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 32, true))),
                sign: enum2,
              }
            };
            break;
          }
          case 1: {
            let variant8;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 8, true)) {
              case 0: {
                var ptr3 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len3 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result3 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr3, len3));
                variant8= {
                  tag: 'message',
                  val: result3
                };
                break;
              }
              case 1: {
                var ptr4 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len4 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result4 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr4, len4));
                variant8= {
                  tag: 'overflow',
                  val: result4
                };
                break;
              }
              case 2: {
                var ptr5 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len5 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
                variant8= {
                  tag: 'div-by-zero',
                  val: result5
                };
                break;
              }
              case 3: {
                var ptr6 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len6 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
                variant8= {
                  tag: 'syntax',
                  val: result6
                };
                break;
              }
              case 4: {
                var ptr7 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len7 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result7 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr7, len7));
                variant8= {
                  tag: 'validation',
                  val: result7
                };
                break;
              }
              default: {
                throw new TypeError('invalid variant discriminant for NumericsError');
              }
            }
            variant9= {
              tag: 'err',
              val: variant8
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="root:component/numerics", function="decimal-to-integer"][Instruction::Return]', {
          funcName: 'decimal-to-integer',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant9;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn3(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let numericsU64ToDecimal;

function u64ToDecimal(arg0) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsU64ToDecimal',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(17);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        _debugLog('[iface="root:component/numerics", function="u64-to-decimal"][Instruction::CallWasm] enter', {
          funcName: 'u64-to-decimal',
          paramCount: 1,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsU64ToDecimal(toUint64(arg0)),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant7;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            let enum0;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 40, true)) {
              case 0: {
                enum0 = 'plus';
                break;
              }
              case 1: {
                enum0 = 'minus';
                break;
              }
              default: {
                throw new TypeError('invalid discriminant specified for Sign');
              }
            }
            variant7= {
              tag: 'ok',
              val: {
                r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 8, true))),
                r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 16, true))),
                r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 24, true))),
                r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 32, true))),
                sign: enum0,
              }
            };
            break;
          }
          case 1: {
            let variant6;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 8, true)) {
              case 0: {
                var ptr1 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len1 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result1 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr1, len1));
                variant6= {
                  tag: 'message',
                  val: result1
                };
                break;
              }
              case 1: {
                var ptr2 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len2 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result2 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr2, len2));
                variant6= {
                  tag: 'overflow',
                  val: result2
                };
                break;
              }
              case 2: {
                var ptr3 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len3 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result3 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr3, len3));
                variant6= {
                  tag: 'div-by-zero',
                  val: result3
                };
                break;
              }
              case 3: {
                var ptr4 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len4 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result4 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr4, len4));
                variant6= {
                  tag: 'syntax',
                  val: result4
                };
                break;
              }
              case 4: {
                var ptr5 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len5 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
                variant6= {
                  tag: 'validation',
                  val: result5
                };
                break;
              }
              default: {
                throw new TypeError('invalid variant discriminant for NumericsError');
              }
            }
            variant7= {
              tag: 'err',
              val: variant6
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="root:component/numerics", function="u64-to-decimal"][Instruction::Return]', {
          funcName: 'u64-to-decimal',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant7;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn3(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let numericsS64ToDecimal;

function s64ToDecimal(arg0) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsS64ToDecimal',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(17);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        _debugLog('[iface="root:component/numerics", function="s64-to-decimal"][Instruction::CallWasm] enter', {
          funcName: 's64-to-decimal',
          paramCount: 1,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsS64ToDecimal(toInt64(arg0)),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant7;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            let enum0;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 40, true)) {
              case 0: {
                enum0 = 'plus';
                break;
              }
              case 1: {
                enum0 = 'minus';
                break;
              }
              default: {
                throw new TypeError('invalid discriminant specified for Sign');
              }
            }
            variant7= {
              tag: 'ok',
              val: {
                r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 8, true))),
                r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 16, true))),
                r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 24, true))),
                r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 32, true))),
                sign: enum0,
              }
            };
            break;
          }
          case 1: {
            let variant6;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 8, true)) {
              case 0: {
                var ptr1 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len1 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result1 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr1, len1));
                variant6= {
                  tag: 'message',
                  val: result1
                };
                break;
              }
              case 1: {
                var ptr2 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len2 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result2 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr2, len2));
                variant6= {
                  tag: 'overflow',
                  val: result2
                };
                break;
              }
              case 2: {
                var ptr3 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len3 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result3 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr3, len3));
                variant6= {
                  tag: 'div-by-zero',
                  val: result3
                };
                break;
              }
              case 3: {
                var ptr4 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len4 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result4 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr4, len4));
                variant6= {
                  tag: 'syntax',
                  val: result4
                };
                break;
              }
              case 4: {
                var ptr5 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len5 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
                variant6= {
                  tag: 'validation',
                  val: result5
                };
                break;
              }
              default: {
                throw new TypeError('invalid variant discriminant for NumericsError');
              }
            }
            variant7= {
              tag: 'err',
              val: variant6
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="root:component/numerics", function="s64-to-decimal"][Instruction::Return]', {
          funcName: 's64-to-decimal',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant7;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn3(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let numericsF64ToDecimal;

function f64ToDecimal(arg0) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsF64ToDecimal',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(17);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        _debugLog('[iface="root:component/numerics", function="f64-to-decimal"][Instruction::CallWasm] enter', {
          funcName: 'f64-to-decimal',
          paramCount: 1,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsF64ToDecimal(+arg0),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant7;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            let enum0;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 40, true)) {
              case 0: {
                enum0 = 'plus';
                break;
              }
              case 1: {
                enum0 = 'minus';
                break;
              }
              default: {
                throw new TypeError('invalid discriminant specified for Sign');
              }
            }
            variant7= {
              tag: 'ok',
              val: {
                r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 8, true))),
                r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 16, true))),
                r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 24, true))),
                r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 32, true))),
                sign: enum0,
              }
            };
            break;
          }
          case 1: {
            let variant6;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 8, true)) {
              case 0: {
                var ptr1 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len1 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result1 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr1, len1));
                variant6= {
                  tag: 'message',
                  val: result1
                };
                break;
              }
              case 1: {
                var ptr2 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len2 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result2 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr2, len2));
                variant6= {
                  tag: 'overflow',
                  val: result2
                };
                break;
              }
              case 2: {
                var ptr3 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len3 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result3 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr3, len3));
                variant6= {
                  tag: 'div-by-zero',
                  val: result3
                };
                break;
              }
              case 3: {
                var ptr4 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len4 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result4 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr4, len4));
                variant6= {
                  tag: 'syntax',
                  val: result4
                };
                break;
              }
              case 4: {
                var ptr5 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len5 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
                variant6= {
                  tag: 'validation',
                  val: result5
                };
                break;
              }
              default: {
                throw new TypeError('invalid variant discriminant for NumericsError');
              }
            }
            variant7= {
              tag: 'err',
              val: variant6
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="root:component/numerics", function="f64-to-decimal"][Instruction::Return]', {
          funcName: 'f64-to-decimal',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant7;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn3(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let numericsStringToDecimal;

function stringToDecimal(arg0) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsStringToDecimal',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(17);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        
        var encodeRes = _utf8AllocateAndEncode(arg0, realloc0, memory0);
        var ptr0= encodeRes.ptr;
        var len0 = encodeRes.len;
        
        _debugLog('[iface="root:component/numerics", function="string-to-decimal"][Instruction::CallWasm] enter', {
          funcName: 'string-to-decimal',
          paramCount: 2,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsStringToDecimal(ptr0, len0),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant8;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            let enum1;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 40, true)) {
              case 0: {
                enum1 = 'plus';
                break;
              }
              case 1: {
                enum1 = 'minus';
                break;
              }
              default: {
                throw new TypeError('invalid discriminant specified for Sign');
              }
            }
            variant8= {
              tag: 'ok',
              val: {
                r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 8, true))),
                r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 16, true))),
                r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 24, true))),
                r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 32, true))),
                sign: enum1,
              }
            };
            break;
          }
          case 1: {
            let variant7;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 8, true)) {
              case 0: {
                var ptr2 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len2 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result2 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr2, len2));
                variant7= {
                  tag: 'message',
                  val: result2
                };
                break;
              }
              case 1: {
                var ptr3 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len3 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result3 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr3, len3));
                variant7= {
                  tag: 'overflow',
                  val: result3
                };
                break;
              }
              case 2: {
                var ptr4 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len4 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result4 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr4, len4));
                variant7= {
                  tag: 'div-by-zero',
                  val: result4
                };
                break;
              }
              case 3: {
                var ptr5 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len5 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
                variant7= {
                  tag: 'syntax',
                  val: result5
                };
                break;
              }
              case 4: {
                var ptr6 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len6 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
                variant7= {
                  tag: 'validation',
                  val: result6
                };
                break;
              }
              default: {
                throw new TypeError('invalid variant discriminant for NumericsError');
              }
            }
            variant8= {
              tag: 'err',
              val: variant7
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="root:component/numerics", function="string-to-decimal"][Instruction::Return]', {
          funcName: 'string-to-decimal',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant8;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn3(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let numericsDecimalToString;

function decimalToString(arg0) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsDecimalToString',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'none',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(0);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var {r0: v0_0, r1: v0_1, r2: v0_2, r3: v0_3, sign: v0_4 } = arg0;
        var val1 = v0_4;
        let enum1;
        switch (val1) {
          case 'plus': {
            enum1 = 0;
            break;
          }
          case 'minus': {
            enum1 = 1;
            break;
          }
          default: {
            if ((v0_4) instanceof Error) {
              console.error(v0_4);
            }
            
            throw new TypeError(`"${val1}" is not one of the cases of sign`);
          }
        }
        _debugLog('[iface="root:component/numerics", function="decimal-to-string"][Instruction::CallWasm] enter', {
          funcName: 'decimal-to-string',
          paramCount: 5,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsDecimalToString(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        var ptr2 = dataView(memory0).getUint32(((ret >>> 0)) + 0, true) >>> 0;
        var len2 = dataView(memory0).getUint32(((ret >>> 0)) + 4, true);
        var result2 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr2, len2));
        _debugLog('[iface="root:component/numerics", function="decimal-to-string"][Instruction::Return]', {
          funcName: 'decimal-to-string',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        task.resolve([result2]);
        const retCopy = result2;
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn4(ret);
        cstate.mayLeave = true;
        task.exit();
        return retCopy;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let numericsEqDecimal;

function eqDecimal(arg0, arg1) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsEqDecimal',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(24);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var {r0: v0_0, r1: v0_1, r2: v0_2, r3: v0_3, sign: v0_4 } = arg0;
        var val1 = v0_4;
        let enum1;
        switch (val1) {
          case 'plus': {
            enum1 = 0;
            break;
          }
          case 'minus': {
            enum1 = 1;
            break;
          }
          default: {
            if ((v0_4) instanceof Error) {
              console.error(v0_4);
            }
            
            throw new TypeError(`"${val1}" is not one of the cases of sign`);
          }
        }
        var {r0: v2_0, r1: v2_1, r2: v2_2, r3: v2_3, sign: v2_4 } = arg1;
        var val3 = v2_4;
        let enum3;
        switch (val3) {
          case 'plus': {
            enum3 = 0;
            break;
          }
          case 'minus': {
            enum3 = 1;
            break;
          }
          default: {
            if ((v2_4) instanceof Error) {
              console.error(v2_4);
            }
            
            throw new TypeError(`"${val3}" is not one of the cases of sign`);
          }
        }
        _debugLog('[iface="root:component/numerics", function="eq-decimal"][Instruction::CallWasm] enter', {
          funcName: 'eq-decimal',
          paramCount: 10,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsEqDecimal(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1, toUint64(v2_0), toUint64(v2_1), toUint64(v2_2), toUint64(v2_3), enum3),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant11;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            var bool4 = dataView(memory0).getUint8(((ret >>> 0)) + 4, true);
            variant11= {
              tag: 'ok',
              val: bool4 == 0 ? false : (bool4 == 1 ? true : throwInvalidBool())
            };
            break;
          }
          case 1: {
            let variant10;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 4, true)) {
              case 0: {
                var ptr5 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true) >>> 0;
                var len5 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true);
                var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
                variant10= {
                  tag: 'message',
                  val: result5
                };
                break;
              }
              case 1: {
                var ptr6 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true) >>> 0;
                var len6 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true);
                var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
                variant10= {
                  tag: 'overflow',
                  val: result6
                };
                break;
              }
              case 2: {
                var ptr7 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true) >>> 0;
                var len7 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true);
                var result7 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr7, len7));
                variant10= {
                  tag: 'div-by-zero',
                  val: result7
                };
                break;
              }
              case 3: {
                var ptr8 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true) >>> 0;
                var len8 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true);
                var result8 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr8, len8));
                variant10= {
                  tag: 'syntax',
                  val: result8
                };
                break;
              }
              case 4: {
                var ptr9 = dataView(memory0).getUint32(((ret >>> 0)) + 8, true) >>> 0;
                var len9 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true);
                var result9 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr9, len9));
                variant10= {
                  tag: 'validation',
                  val: result9
                };
                break;
              }
              default: {
                throw new TypeError('invalid variant discriminant for NumericsError');
              }
            }
            variant11= {
              tag: 'err',
              val: variant10
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="root:component/numerics", function="eq-decimal"][Instruction::Return]', {
          funcName: 'eq-decimal',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant11;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn5(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let numericsCmpDecimal;

function cmpDecimal(arg0, arg1) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsCmpDecimal',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'none',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(20);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (null!== null) {
    task.setReturnMemoryIdx(null);
    task.setReturnMemory((() => null)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var {r0: v0_0, r1: v0_1, r2: v0_2, r3: v0_3, sign: v0_4 } = arg0;
        var val1 = v0_4;
        let enum1;
        switch (val1) {
          case 'plus': {
            enum1 = 0;
            break;
          }
          case 'minus': {
            enum1 = 1;
            break;
          }
          default: {
            if ((v0_4) instanceof Error) {
              console.error(v0_4);
            }
            
            throw new TypeError(`"${val1}" is not one of the cases of sign`);
          }
        }
        var {r0: v2_0, r1: v2_1, r2: v2_2, r3: v2_3, sign: v2_4 } = arg1;
        var val3 = v2_4;
        let enum3;
        switch (val3) {
          case 'plus': {
            enum3 = 0;
            break;
          }
          case 'minus': {
            enum3 = 1;
            break;
          }
          default: {
            if ((v2_4) instanceof Error) {
              console.error(v2_4);
            }
            
            throw new TypeError(`"${val3}" is not one of the cases of sign`);
          }
        }
        _debugLog('[iface="root:component/numerics", function="cmp-decimal"][Instruction::CallWasm] enter', {
          funcName: 'cmp-decimal',
          paramCount: 10,
          async: false,
          postReturn: false,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsCmpDecimal(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1, toUint64(v2_0), toUint64(v2_1), toUint64(v2_2), toUint64(v2_3), enum3),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let enum4;
        switch (ret) {
          case 0: {
            enum4 = 'less';
            break;
          }
          case 1: {
            enum4 = 'equal';
            break;
          }
          case 2: {
            enum4 = 'greater';
            break;
          }
          default: {
            throw new TypeError('invalid discriminant specified for Ordering');
          }
        }
        _debugLog('[iface="root:component/numerics", function="cmp-decimal"][Instruction::Return]', {
          funcName: 'cmp-decimal',
          paramCount: 1,
          async: false,
          postReturn: false
        });
        task.resolve([enum4]);
        task.exit();
        return enum4;
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let numericsAddDecimal;

function addDecimal(arg0, arg1) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsAddDecimal',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(17);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var {r0: v0_0, r1: v0_1, r2: v0_2, r3: v0_3, sign: v0_4 } = arg0;
        var val1 = v0_4;
        let enum1;
        switch (val1) {
          case 'plus': {
            enum1 = 0;
            break;
          }
          case 'minus': {
            enum1 = 1;
            break;
          }
          default: {
            if ((v0_4) instanceof Error) {
              console.error(v0_4);
            }
            
            throw new TypeError(`"${val1}" is not one of the cases of sign`);
          }
        }
        var {r0: v2_0, r1: v2_1, r2: v2_2, r3: v2_3, sign: v2_4 } = arg1;
        var val3 = v2_4;
        let enum3;
        switch (val3) {
          case 'plus': {
            enum3 = 0;
            break;
          }
          case 'minus': {
            enum3 = 1;
            break;
          }
          default: {
            if ((v2_4) instanceof Error) {
              console.error(v2_4);
            }
            
            throw new TypeError(`"${val3}" is not one of the cases of sign`);
          }
        }
        _debugLog('[iface="root:component/numerics", function="add-decimal"][Instruction::CallWasm] enter', {
          funcName: 'add-decimal',
          paramCount: 10,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsAddDecimal(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1, toUint64(v2_0), toUint64(v2_1), toUint64(v2_2), toUint64(v2_3), enum3),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant11;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            let enum4;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 40, true)) {
              case 0: {
                enum4 = 'plus';
                break;
              }
              case 1: {
                enum4 = 'minus';
                break;
              }
              default: {
                throw new TypeError('invalid discriminant specified for Sign');
              }
            }
            variant11= {
              tag: 'ok',
              val: {
                r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 8, true))),
                r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 16, true))),
                r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 24, true))),
                r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 32, true))),
                sign: enum4,
              }
            };
            break;
          }
          case 1: {
            let variant10;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 8, true)) {
              case 0: {
                var ptr5 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len5 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
                variant10= {
                  tag: 'message',
                  val: result5
                };
                break;
              }
              case 1: {
                var ptr6 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len6 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
                variant10= {
                  tag: 'overflow',
                  val: result6
                };
                break;
              }
              case 2: {
                var ptr7 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len7 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result7 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr7, len7));
                variant10= {
                  tag: 'div-by-zero',
                  val: result7
                };
                break;
              }
              case 3: {
                var ptr8 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len8 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result8 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr8, len8));
                variant10= {
                  tag: 'syntax',
                  val: result8
                };
                break;
              }
              case 4: {
                var ptr9 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len9 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result9 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr9, len9));
                variant10= {
                  tag: 'validation',
                  val: result9
                };
                break;
              }
              default: {
                throw new TypeError('invalid variant discriminant for NumericsError');
              }
            }
            variant11= {
              tag: 'err',
              val: variant10
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="root:component/numerics", function="add-decimal"][Instruction::Return]', {
          funcName: 'add-decimal',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant11;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn3(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let numericsSubDecimal;

function subDecimal(arg0, arg1) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsSubDecimal',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(17);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var {r0: v0_0, r1: v0_1, r2: v0_2, r3: v0_3, sign: v0_4 } = arg0;
        var val1 = v0_4;
        let enum1;
        switch (val1) {
          case 'plus': {
            enum1 = 0;
            break;
          }
          case 'minus': {
            enum1 = 1;
            break;
          }
          default: {
            if ((v0_4) instanceof Error) {
              console.error(v0_4);
            }
            
            throw new TypeError(`"${val1}" is not one of the cases of sign`);
          }
        }
        var {r0: v2_0, r1: v2_1, r2: v2_2, r3: v2_3, sign: v2_4 } = arg1;
        var val3 = v2_4;
        let enum3;
        switch (val3) {
          case 'plus': {
            enum3 = 0;
            break;
          }
          case 'minus': {
            enum3 = 1;
            break;
          }
          default: {
            if ((v2_4) instanceof Error) {
              console.error(v2_4);
            }
            
            throw new TypeError(`"${val3}" is not one of the cases of sign`);
          }
        }
        _debugLog('[iface="root:component/numerics", function="sub-decimal"][Instruction::CallWasm] enter', {
          funcName: 'sub-decimal',
          paramCount: 10,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsSubDecimal(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1, toUint64(v2_0), toUint64(v2_1), toUint64(v2_2), toUint64(v2_3), enum3),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant11;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            let enum4;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 40, true)) {
              case 0: {
                enum4 = 'plus';
                break;
              }
              case 1: {
                enum4 = 'minus';
                break;
              }
              default: {
                throw new TypeError('invalid discriminant specified for Sign');
              }
            }
            variant11= {
              tag: 'ok',
              val: {
                r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 8, true))),
                r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 16, true))),
                r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 24, true))),
                r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 32, true))),
                sign: enum4,
              }
            };
            break;
          }
          case 1: {
            let variant10;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 8, true)) {
              case 0: {
                var ptr5 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len5 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
                variant10= {
                  tag: 'message',
                  val: result5
                };
                break;
              }
              case 1: {
                var ptr6 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len6 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
                variant10= {
                  tag: 'overflow',
                  val: result6
                };
                break;
              }
              case 2: {
                var ptr7 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len7 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result7 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr7, len7));
                variant10= {
                  tag: 'div-by-zero',
                  val: result7
                };
                break;
              }
              case 3: {
                var ptr8 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len8 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result8 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr8, len8));
                variant10= {
                  tag: 'syntax',
                  val: result8
                };
                break;
              }
              case 4: {
                var ptr9 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len9 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result9 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr9, len9));
                variant10= {
                  tag: 'validation',
                  val: result9
                };
                break;
              }
              default: {
                throw new TypeError('invalid variant discriminant for NumericsError');
              }
            }
            variant11= {
              tag: 'err',
              val: variant10
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="root:component/numerics", function="sub-decimal"][Instruction::Return]', {
          funcName: 'sub-decimal',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant11;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn3(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let numericsMulDecimal;

function mulDecimal(arg0, arg1) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsMulDecimal',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(17);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var {r0: v0_0, r1: v0_1, r2: v0_2, r3: v0_3, sign: v0_4 } = arg0;
        var val1 = v0_4;
        let enum1;
        switch (val1) {
          case 'plus': {
            enum1 = 0;
            break;
          }
          case 'minus': {
            enum1 = 1;
            break;
          }
          default: {
            if ((v0_4) instanceof Error) {
              console.error(v0_4);
            }
            
            throw new TypeError(`"${val1}" is not one of the cases of sign`);
          }
        }
        var {r0: v2_0, r1: v2_1, r2: v2_2, r3: v2_3, sign: v2_4 } = arg1;
        var val3 = v2_4;
        let enum3;
        switch (val3) {
          case 'plus': {
            enum3 = 0;
            break;
          }
          case 'minus': {
            enum3 = 1;
            break;
          }
          default: {
            if ((v2_4) instanceof Error) {
              console.error(v2_4);
            }
            
            throw new TypeError(`"${val3}" is not one of the cases of sign`);
          }
        }
        _debugLog('[iface="root:component/numerics", function="mul-decimal"][Instruction::CallWasm] enter', {
          funcName: 'mul-decimal',
          paramCount: 10,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsMulDecimal(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1, toUint64(v2_0), toUint64(v2_1), toUint64(v2_2), toUint64(v2_3), enum3),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant11;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            let enum4;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 40, true)) {
              case 0: {
                enum4 = 'plus';
                break;
              }
              case 1: {
                enum4 = 'minus';
                break;
              }
              default: {
                throw new TypeError('invalid discriminant specified for Sign');
              }
            }
            variant11= {
              tag: 'ok',
              val: {
                r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 8, true))),
                r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 16, true))),
                r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 24, true))),
                r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 32, true))),
                sign: enum4,
              }
            };
            break;
          }
          case 1: {
            let variant10;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 8, true)) {
              case 0: {
                var ptr5 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len5 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
                variant10= {
                  tag: 'message',
                  val: result5
                };
                break;
              }
              case 1: {
                var ptr6 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len6 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
                variant10= {
                  tag: 'overflow',
                  val: result6
                };
                break;
              }
              case 2: {
                var ptr7 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len7 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result7 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr7, len7));
                variant10= {
                  tag: 'div-by-zero',
                  val: result7
                };
                break;
              }
              case 3: {
                var ptr8 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len8 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result8 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr8, len8));
                variant10= {
                  tag: 'syntax',
                  val: result8
                };
                break;
              }
              case 4: {
                var ptr9 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len9 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result9 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr9, len9));
                variant10= {
                  tag: 'validation',
                  val: result9
                };
                break;
              }
              default: {
                throw new TypeError('invalid variant discriminant for NumericsError');
              }
            }
            variant11= {
              tag: 'err',
              val: variant10
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="root:component/numerics", function="mul-decimal"][Instruction::Return]', {
          funcName: 'mul-decimal',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant11;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn3(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let numericsDivDecimal;

function divDecimal(arg0, arg1) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsDivDecimal',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(17);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var {r0: v0_0, r1: v0_1, r2: v0_2, r3: v0_3, sign: v0_4 } = arg0;
        var val1 = v0_4;
        let enum1;
        switch (val1) {
          case 'plus': {
            enum1 = 0;
            break;
          }
          case 'minus': {
            enum1 = 1;
            break;
          }
          default: {
            if ((v0_4) instanceof Error) {
              console.error(v0_4);
            }
            
            throw new TypeError(`"${val1}" is not one of the cases of sign`);
          }
        }
        var {r0: v2_0, r1: v2_1, r2: v2_2, r3: v2_3, sign: v2_4 } = arg1;
        var val3 = v2_4;
        let enum3;
        switch (val3) {
          case 'plus': {
            enum3 = 0;
            break;
          }
          case 'minus': {
            enum3 = 1;
            break;
          }
          default: {
            if ((v2_4) instanceof Error) {
              console.error(v2_4);
            }
            
            throw new TypeError(`"${val3}" is not one of the cases of sign`);
          }
        }
        _debugLog('[iface="root:component/numerics", function="div-decimal"][Instruction::CallWasm] enter', {
          funcName: 'div-decimal',
          paramCount: 10,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsDivDecimal(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1, toUint64(v2_0), toUint64(v2_1), toUint64(v2_2), toUint64(v2_3), enum3),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant11;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            let enum4;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 40, true)) {
              case 0: {
                enum4 = 'plus';
                break;
              }
              case 1: {
                enum4 = 'minus';
                break;
              }
              default: {
                throw new TypeError('invalid discriminant specified for Sign');
              }
            }
            variant11= {
              tag: 'ok',
              val: {
                r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 8, true))),
                r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 16, true))),
                r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 24, true))),
                r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 32, true))),
                sign: enum4,
              }
            };
            break;
          }
          case 1: {
            let variant10;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 8, true)) {
              case 0: {
                var ptr5 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len5 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
                variant10= {
                  tag: 'message',
                  val: result5
                };
                break;
              }
              case 1: {
                var ptr6 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len6 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
                variant10= {
                  tag: 'overflow',
                  val: result6
                };
                break;
              }
              case 2: {
                var ptr7 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len7 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result7 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr7, len7));
                variant10= {
                  tag: 'div-by-zero',
                  val: result7
                };
                break;
              }
              case 3: {
                var ptr8 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len8 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result8 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr8, len8));
                variant10= {
                  tag: 'syntax',
                  val: result8
                };
                break;
              }
              case 4: {
                var ptr9 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len9 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result9 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr9, len9));
                variant10= {
                  tag: 'validation',
                  val: result9
                };
                break;
              }
              default: {
                throw new TypeError('invalid variant discriminant for NumericsError');
              }
            }
            variant11= {
              tag: 'err',
              val: variant10
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="root:component/numerics", function="div-decimal"][Instruction::Return]', {
          funcName: 'div-decimal',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant11;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn3(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
let numericsLog10Decimal;

function log10Decimal(arg0) {
  
  const hostProvided = false;
  getOrCreateAsyncState(0).throwIfTrapped();
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    preserveFutureResult: false,
    entryFnName: 'numericsLog10Decimal',
    getCallbackFn: () => null,
    callbackFnName: null,
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  task.setCalleeIsAsync(false);
  task.setFuncTypeIsAsync(false);
  task.setReturnResultTypeIdx(17);
  
  const started = task.enterSync();
  CURRENT_TASK_MAY_BLOCK.value = task.mayBlock() ? 1 : 0;
  
  if (0!== null) {
    task.setReturnMemoryIdx(0);
    task.setReturnMemory((() => memory0)());
  }
  
  
  return _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => {
      try {
        
        var {r0: v0_0, r1: v0_1, r2: v0_2, r3: v0_3, sign: v0_4 } = arg0;
        var val1 = v0_4;
        let enum1;
        switch (val1) {
          case 'plus': {
            enum1 = 0;
            break;
          }
          case 'minus': {
            enum1 = 1;
            break;
          }
          default: {
            if ((v0_4) instanceof Error) {
              console.error(v0_4);
            }
            
            throw new TypeError(`"${val1}" is not one of the cases of sign`);
          }
        }
        _debugLog('[iface="root:component/numerics", function="log10-decimal"][Instruction::CallWasm] enter', {
          funcName: 'log10-decimal',
          paramCount: 5,
          async: false,
          postReturn: true,
        });
        
        let ret;
        
        try {
          ret =  _withGlobalCurrentTaskMeta({
            taskID: task.id(),
            componentIdx: task.componentIdx(),
            fn: () => numericsLog10Decimal(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1),
          });
        } catch (err) {
          
          _debugLog('[Instruction::CallWasm] error during sync call', {
            taskID: task.id(),
            err,
          });
          getOrCreateAsyncState(0).markTrapped(err);
          task.setErrored(err);
          task.reject(err);
          task.exit();
          throw err;
          
        }
        task.endFirstSlice();
        
        let variant9;
        switch (dataView(memory0).getUint8(((ret >>> 0)) + 0, true)) {
          case 0: {
            let enum2;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 40, true)) {
              case 0: {
                enum2 = 'plus';
                break;
              }
              case 1: {
                enum2 = 'minus';
                break;
              }
              default: {
                throw new TypeError('invalid discriminant specified for Sign');
              }
            }
            variant9= {
              tag: 'ok',
              val: {
                r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 8, true))),
                r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 16, true))),
                r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 24, true))),
                r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(((ret >>> 0)) + 32, true))),
                sign: enum2,
              }
            };
            break;
          }
          case 1: {
            let variant8;
            switch (dataView(memory0).getUint8(((ret >>> 0)) + 8, true)) {
              case 0: {
                var ptr3 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len3 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result3 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr3, len3));
                variant8= {
                  tag: 'message',
                  val: result3
                };
                break;
              }
              case 1: {
                var ptr4 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len4 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result4 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr4, len4));
                variant8= {
                  tag: 'overflow',
                  val: result4
                };
                break;
              }
              case 2: {
                var ptr5 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len5 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
                variant8= {
                  tag: 'div-by-zero',
                  val: result5
                };
                break;
              }
              case 3: {
                var ptr6 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len6 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
                variant8= {
                  tag: 'syntax',
                  val: result6
                };
                break;
              }
              case 4: {
                var ptr7 = dataView(memory0).getUint32(((ret >>> 0)) + 12, true) >>> 0;
                var len7 = dataView(memory0).getUint32(((ret >>> 0)) + 16, true);
                var result7 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr7, len7));
                variant8= {
                  tag: 'validation',
                  val: result7
                };
                break;
              }
              default: {
                throw new TypeError('invalid variant discriminant for NumericsError');
              }
            }
            variant9= {
              tag: 'err',
              val: variant8
            };
            break;
          }
          default: {
            throw new TypeError('invalid variant discriminant for expected');
          }
        }
        _debugLog('[iface="root:component/numerics", function="log10-decimal"][Instruction::Return]', {
          funcName: 'log10-decimal',
          paramCount: 1,
          async: false,
          postReturn: true
        });
        const retCopy = variant9;
        task.resolve([retCopy.val]);
        
        let cstate = getOrCreateAsyncState(0);
        cstate.mayLeave = false;
        postReturn3(ret);
        cstate.mayLeave = true;
        task.exit();
        
        
        
        if (typeof retCopy === 'object' && retCopy.tag === 'err') {
          throw new ComponentError(retCopy.val);
        }
        return retCopy.val;
        
        
      } catch (err) {
        if (!task.isResolvedState()) {
          task.setErrored(err);
          task.reject(err);
        }
        if (!task.isExited()) { task.exit({ skipExclusiveLockCheck: true }); }
        throw err;
      }
    },
  });
  
}
const trampoline0 = rscTableCreateOwn.bind(null, handleTable0);

const $init = (() => {
  let gen= (function* _initGenerator () {
    const module0 = fetchCompile(new URL('./kontor-sdk.core.wasm', import.meta.url));
    const module1 = base64Compile('AGFzbQEAAAABBQFgAX8AAwIBAAQFAXABAQEHEAIBMAAACCRpbXBvcnRzAQAKCwEJACAAQQARAAALAC8JcHJvZHVjZXJzAQxwcm9jZXNzZWQtYnkBDXdpdC1jb21wb25lbnQHMC4yNjIuMAAnBG5hbWUAExJ3aXQtY29tcG9uZW50OnNoaW0BCwEACGR0b3Itd2l0');
    const module2 = base64Compile('AGFzbQEAAAABBQFgAX8AAh8CBmFjdHVhbAEwAAAEc2hpbQgkaW1wb3J0cwFwAQEBCQcBAEEACwEAAC8JcHJvZHVjZXJzAQxwcm9jZXNzZWQtYnkBDXdpdC1jb21wb25lbnQHMC4yNjIuMAAiBG5hbWUAFRR3aXQtY29tcG9uZW50OmZpeHVwcwEEAQABMA');
    const instanceFlags0 = new WebAssembly.Global({ value: "i32", mutable: true }, 1);
    INSTANCE_FLAGS.set(0, instanceFlags0);
    ({ exports: exports0 } = yield instantiateCore(yield module1));
    ({ exports: exports1 } = yield instantiateCore(yield module0, {
      '[export]root:component/wit-codec': {
        '[resource-new]wit': Object.assign(_guardTrap(0, _guardMayLeave(0, trampoline0), true), { _jcoMaySuspend: false }),
      },
    }));
    ({ exports: exports2 } = yield instantiateCore(yield module2, {
      actual: {
        '0': Object.assign(exports1['root:component/wit-codec#[dtor]wit'], { _jcoMaySuspend: false }),
      },
      shim: {
        $imports: exports0.$imports,
      },
    }));
    memory0 = exports1.memory;
    realloc0 = (oldPtr, oldSize, align, newSize) => exports1.cabi_realloc(oldPtr, oldSize, align, newSize) >>> 0;
    
    try {
      const realloc0Promising = WebAssembly.promising(exports1.cabi_realloc);
      realloc0Async = async (oldPtr, oldSize, align, newSize) => (await realloc0Promising(oldPtr, oldSize, align, newSize)) >>> 0;
    } catch(err) {
      realloc0Async = realloc0;
    }
    
    postReturn0 = exports1['cabi_post_aggregate-signing-message'];
    
    try {
      postReturn0Async = WebAssembly.promising(exports1['cabi_post_aggregate-signing-message']);
    } catch(err) {
      postReturn0Async = exports1['cabi_post_aggregate-signing-message'];
    }
    
    postReturn1 = exports1['cabi_post_bls-verify'];
    
    try {
      postReturn1Async = WebAssembly.promising(exports1['cabi_post_bls-verify']);
    } catch(err) {
      postReturn1Async = exports1['cabi_post_bls-verify'];
    }
    
    postReturn2 = exports1['cabi_post_validate-wit'];
    
    try {
      postReturn2Async = WebAssembly.promising(exports1['cabi_post_validate-wit']);
    } catch(err) {
      postReturn2Async = exports1['cabi_post_validate-wit'];
    }
    
    postReturn3 = exports1['cabi_post_root:component/numerics#add-decimal'];
    
    try {
      postReturn3Async = WebAssembly.promising(exports1['cabi_post_root:component/numerics#add-decimal']);
    } catch(err) {
      postReturn3Async = exports1['cabi_post_root:component/numerics#add-decimal'];
    }
    
    postReturn4 = exports1['cabi_post_root:component/numerics#decimal-to-string'];
    
    try {
      postReturn4Async = WebAssembly.promising(exports1['cabi_post_root:component/numerics#decimal-to-string']);
    } catch(err) {
      postReturn4Async = exports1['cabi_post_root:component/numerics#decimal-to-string'];
    }
    
    postReturn5 = exports1['cabi_post_root:component/numerics#eq-decimal'];
    
    try {
      postReturn5Async = WebAssembly.promising(exports1['cabi_post_root:component/numerics#eq-decimal']);
    } catch(err) {
      postReturn5Async = exports1['cabi_post_root:component/numerics#eq-decimal'];
    }
    
    exports1SerializeInst = exports1['serialize-inst'];
    exports1DeserializeInst = exports1['deserialize-inst'];
    exports1BlsSecretKeyGen = exports1['bls-secret-key-gen'];
    exports1BlsSecretFromSeedEip2333 = exports1['bls-secret-from-seed-eip2333'];
    exports1BlsPubkeyFromSecret = exports1['bls-pubkey-from-secret'];
    exports1BlsSign = exports1['bls-sign'];
    exports1BlsVerify = exports1['bls-verify'];
    exports1AggregateSigningMessage = exports1['aggregate-signing-message'];
    exports1BlsAggregateSignatures = exports1['bls-aggregate-signatures'];
    exports1ValidateWit = exports1['validate-wit'];
    witCodecConstructorWit = exports1['root:component/wit-codec#[constructor]wit'];
    witCodecMethodWitEncodeCall = exports1['root:component/wit-codec#[method]wit.encode-call'];
    witCodecMethodWitDecodeResult = exports1['root:component/wit-codec#[method]wit.decode-result'];
    witCodecMethodWitParse = exports1['root:component/wit-codec#[method]wit.parse'];
    numericsU64ToInteger = exports1['root:component/numerics#u64-to-integer'];
    numericsS64ToInteger = exports1['root:component/numerics#s64-to-integer'];
    numericsStringToInteger = exports1['root:component/numerics#string-to-integer'];
    numericsIntegerToString = exports1['root:component/numerics#integer-to-string'];
    numericsEqInteger = exports1['root:component/numerics#eq-integer'];
    numericsCmpInteger = exports1['root:component/numerics#cmp-integer'];
    numericsAddInteger = exports1['root:component/numerics#add-integer'];
    numericsSubInteger = exports1['root:component/numerics#sub-integer'];
    numericsMulInteger = exports1['root:component/numerics#mul-integer'];
    numericsDivInteger = exports1['root:component/numerics#div-integer'];
    numericsMulAddDivRemInteger = exports1['root:component/numerics#mul-add-div-rem-integer'];
    numericsSqrtInteger = exports1['root:component/numerics#sqrt-integer'];
    numericsIntegerToDecimal = exports1['root:component/numerics#integer-to-decimal'];
    numericsDecimalToInteger = exports1['root:component/numerics#decimal-to-integer'];
    numericsU64ToDecimal = exports1['root:component/numerics#u64-to-decimal'];
    numericsS64ToDecimal = exports1['root:component/numerics#s64-to-decimal'];
    numericsF64ToDecimal = exports1['root:component/numerics#f64-to-decimal'];
    numericsStringToDecimal = exports1['root:component/numerics#string-to-decimal'];
    numericsDecimalToString = exports1['root:component/numerics#decimal-to-string'];
    numericsEqDecimal = exports1['root:component/numerics#eq-decimal'];
    numericsCmpDecimal = exports1['root:component/numerics#cmp-decimal'];
    numericsAddDecimal = exports1['root:component/numerics#add-decimal'];
    numericsSubDecimal = exports1['root:component/numerics#sub-decimal'];
    numericsMulDecimal = exports1['root:component/numerics#mul-decimal'];
    numericsDivDecimal = exports1['root:component/numerics#div-decimal'];
    numericsLog10Decimal = exports1['root:component/numerics#log10-decimal'];
  })();
  let promise, resolve, reject;
  function normalizeInstantiationError(e) {
    // Native JSPI rejects a suspending import called from a
    // core start function before entering its JS wrapper.
    // At component instantiation time that always means the
    // implicit synchronous task attempted to block.
    if (typeof WebAssembly !== 'undefined' && typeof WebAssembly.SuspendError === 'function' && e instanceof WebAssembly.SuspendError) {
      return new WebAssembly.RuntimeError('cannot block a synchronous task before returning');
    }
    return e;
  }
  function runNext(value) {
    try {
      let done;
      do {
        ({ value, done } = gen.next(value));
      } while (!(value instanceof Promise) && !done);
      if (done) {
        if (resolve) resolve(value);
        else return value;
      }
      if (!promise) promise = new Promise((_resolve, _reject) => (resolve = _resolve, reject= _reject));
      value.then(runNext, e => reject(normalizeInstantiationError(e)));
    }
    catch (e) {
      e = normalizeInstantiationError(e);
      if (reject) reject(e);
      else throw e;
    }
  }
  const maybeSyncReturn = runNext(null);
  return promise || maybeSyncReturn;
})();

await $init;
const numerics = {
  addDecimal: addDecimal,
  addInteger: addInteger,
  cmpDecimal: cmpDecimal,
  cmpInteger: cmpInteger,
  decimalToInteger: decimalToInteger,
  decimalToString: decimalToString,
  divDecimal: divDecimal,
  divInteger: divInteger,
  eqDecimal: eqDecimal,
  eqInteger: eqInteger,
  f64ToDecimal: f64ToDecimal,
  integerToDecimal: integerToDecimal,
  integerToString: integerToString,
  log10Decimal: log10Decimal,
  mulAddDivRemInteger: mulAddDivRemInteger,
  mulDecimal: mulDecimal,
  mulInteger: mulInteger,
  s64ToDecimal: s64ToDecimal,
  s64ToInteger: s64ToInteger,
  sqrtInteger: sqrtInteger,
  stringToDecimal: stringToDecimal,
  stringToInteger: stringToInteger,
  subDecimal: subDecimal,
  subInteger: subInteger,
  u64ToDecimal: u64ToDecimal,
  u64ToInteger: u64ToInteger,
  
};
const witCodec = {
  Wit: Wit,
  
};

export { numerics, witCodec, aggregateSigningMessage, blsAggregateSignatures, blsPubkeyFromSecret, blsSecretFromSeedEip2333, blsSecretKeyGen, blsSign, blsVerify, deserializeInst, numerics as 'root:component/numerics', witCodec as 'root:component/wit-codec', serializeInst, validateWit,  }
export const _util = {
  
}

