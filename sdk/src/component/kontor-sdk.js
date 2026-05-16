"use components";

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
const symbolDispose = Symbol.dispose || Symbol.for('dispose');
const symbolAsyncIterator = Symbol.asyncIterator;
const symbolIterator = Symbol.iterator;

const _debugLog = (...args) => {
  if (!globalThis?.process?.env?.JCO_DEBUG) { return; }
  console.debug(...args);
};
const ASYNC_DETERMINISM = 'random';
const GLOBAL_COMPONENT_MEMORY_MAP = new Map();
const CURRENT_TASK_META = {};

function _getGlobalCurrentTaskMeta(componentIdx) {
  const v = CURRENT_TASK_META[componentIdx];
  if (v === undefined) { return v; }
  return { ...v };
}

function _setGlobalCurrentTaskMeta(args) {
  if (!args) { throw new TypeError('args missing'); }
  if (args.taskID === undefined) { throw new TypeError('missing task ID'); }
  if (args.componentIdx === undefined) { throw new TypeError('missing component idx'); }
  const { taskID, componentIdx } = args;
  return CURRENT_TASK_META[componentIdx] = { taskID, componentIdx };
}

function _withGlobalCurrentTaskMeta(args) {
  _debugLog('[_withGlobalCurrentTaskMeta()] args', args);
  if (!args) { throw new TypeError('args missing'); }
  if (args.taskID === undefined) { throw new TypeError('missing task ID'); }
  if (args.componentIdx === undefined) { throw new TypeError('missing component idx'); }
  if (!args.fn) { throw new TypeError('missing fn'); }
  const { taskID, componentIdx, fn } = args;
  
  try {
    CURRENT_TASK_META[componentIdx] = { taskID, componentIdx };
    return fn();
  } catch (err) {
    _debugLog("error while executing sync callee/callback", {
      ...args,
      err,
    });
    throw err;
  } finally {
    CURRENT_TASK_META[componentIdx] = null;
  }
}

async function _withGlobalCurrentTaskMetaAsync(args) {
  _debugLog('[_withGlobalCurrentTaskMetaAsync()] args', args);
  if (!args) { throw new TypeError('args missing'); }
  if (args.taskID === undefined) { throw new TypeError('missing task ID'); }
  if (args.componentIdx === undefined) { throw new TypeError('missing component idx'); }
  if (!args.fn) { throw new TypeError('missing fn'); }
  const { taskID, componentIdx, fn } = args;
  
  // If there is already an async task executing, we must wait for it
  // to complete before we can can run the closure we were given
  //
  let current = CURRENT_TASK_META[componentIdx];
  let cstate;
  if (current && current.taskID !== taskID) {
    cstate = getOrCreateAsyncState(componentIdx);
    while (current && current.taskID !== taskID) {
      const { promise, resolve } = Promise.withResolvers();
      cstate.onNextExclusiveRelease(resolve);
      await promise;
      current = CURRENT_TASK_META[componentIdx];
    }
    
    // Since we've just waited for the component to not be locked, re-lock
    // exclusivity so we can run the fn below (likely a callee/callback)
    cstate.exclusiveLock();
  }
  
  try {
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
  }
}

async function _clearCurrentTask(args) {
  _debugLog('[_clearCurrentTask()] args', args);
  if (!args) { throw new TypeError('args missing'); }
  if (args.taskID === undefined) { throw new TypeError('missing task ID'); }
  if (args.componentIdx === undefined) { throw new TypeError('missing component idx'); }
  const { taskID, componentIdx } = args;
  
  const meta = CURRENT_TASK_META[componentIdx];
  if (!meta) { throw new Error(`missing current task meta for component idx [${componentIdx}]n`); }
  
  if (meta.taskID !== taskID) {
    throw new Error(`task ID [${meta.taskID}] != requested ID [${taskID}]`);
  }
  if (meta.componentIdx !== componentIdx) {
    throw new Error(`component idx [${meta.componentIdx}] != requested idx [${componentIdx}]`);
  }
  
  CURRENT_TASK_META[componentIdx] = null;
}

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

function registerGlobalMemoryForComponent(args) {
  const { componentIdx, memory, memoryIdx } = args ?? {};
  if (componentIdx === undefined) { throw new TypeError('missing component idx'); }
  if (memory === undefined && memoryIdx === undefined) { throw new TypeError('missing both memory & memory idx'); }
  let inner = GLOBAL_COMPONENT_MEMORY_MAP.get(componentIdx);
  if (!inner) {
    inner = {};
    GLOBAL_COMPONENT_MEMORY_MAP.set(componentIdx, inner);
  }
  
  inner[memoryIdx] = { memory, memoryIdx, componentIdx };
}

class RepTable {
  #data = [0, null];
  #target;
  
  constructor(args) {
    this.target = args?.target;
  }
  
  data() { return this.#data; }
  
  insert(val) {
    _debugLog('[RepTable#insert()] args', { val, target: this.target });
    const freeIdx = this.#data[0];
    if (freeIdx === 0) {
      this.#data.push(val);
      this.#data.push(null);
      const rep = (this.#data.length >> 1) - 1;
      _debugLog('[RepTable#insert()] inserted', { val, target: this.target, rep });
      return rep;
    }
    this.#data[0] = this.#data[freeIdx << 1];
    const placementIdx = freeIdx << 1;
    this.#data[placementIdx] = val;
    this.#data[placementIdx + 1] = null;
    _debugLog('[RepTable#insert()] inserted', { val, target: this.target, rep: freeIdx });
    return freeIdx;
  }
  
  get(rep) {
    _debugLog('[RepTable#get()] args', { rep, target: this.target });
    if (rep === 0) { throw new Error('invalid resource rep during get, (cannot be 0)'); }
    
    const baseIdx = rep << 1;
    const val = this.#data[baseIdx];
    return val;
  }
  
  contains(rep) {
    _debugLog('[RepTable#contains()] args', { rep, target: this.target });
    if (rep === 0) { throw new Error('invalid resource rep during contains, (cannot be 0)'); }
    
    const baseIdx = rep << 1;
    return !!this.#data[baseIdx];
  }
  
  remove(rep) {
    _debugLog('[RepTable#remove()] args', { rep, target: this.target });
    if (rep === 0) { throw new Error('invalid resource rep during remove, (cannot be 0)'); }
    if (this.#data.length === 2) { throw new Error('invalid'); }
    
    const baseIdx = rep << 1;
    const val = this.#data[baseIdx];
    
    this.#data[baseIdx] = this.#data[0];
    this.#data[0] = rep;
    
    return val;
  }
  
  clear() {
    _debugLog('[RepTable#clear()] args', { rep, target: this.target });
    this.#data = [0, null];
  }
}
const _coinFlip = () => { return Math.random() > 0.5; };
let SCOPE_ID = 0;
const I32_MIN = -2_147_483_648;
const I32_MAX = 2_147_483_647;

function _isValidNumericPrimitive(ty, v) {
  if (v === undefined || v === null) { return false; }
  switch (ty) {
    case 'bool':
    return v === 0 || v === 1;
    break;
    case 'u8':
    return v >= 0 && v <= 255;
    break;
    case 's8':
    return v >= -128 && v <= 127;
    break;
    case 'u16':
    return v >= 0 && v <= 65535;
    break;
    case 's16':
    return v >= -32768 && v <= 32767;
    case 'u32':
    return v >= 0 && v <= 4_294_967_295;
    case 's32':
    return v >= -2_147_483_648 && v <= 2_147_483_647;
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
const _typeCheckValidI32 = (n) => typeof n === 'number' && n >= I32_MIN && n <= I32_MAX;

const _typeCheckAsyncFn= (f) => {
  return f instanceof ASYNC_FN_CTOR;
};

let RESOURCE_CALL_BORROWS = [];const ASYNC_FN_CTOR = (async () => {}).constructor;

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
  
  if (taskID !== undefined) {
    const last = tasks[tasks.length - 1];
    if (last.id !== taskID) {
      // throw new Error('current task does not match expected task ID');
      return;
    }
  }
  
  ASYNC_CURRENT_TASK_IDS.pop();
  ASYNC_CURRENT_COMPONENT_IDXS.pop();
  
  const taskMeta = tasks.pop();
  return taskMeta.task;
}
const CURRENT_TASK_MAY_BLOCK = new WebAssembly.Global({ value: 'i32', mutable: true }, 0);
const ASYNC_CURRENT_TASK_IDS = [];
const ASYNC_CURRENT_COMPONENT_IDXS = [];

function unpackCallbackResult(result) {
  if (!(_typeCheckValidI32(result))) { throw new Error('invalid callback return value [' + result + '], not a valid i32'); }
  const eventCode = result & 0xF;
  if (eventCode < 0 || eventCode > 3) {
    throw new Error('invalid async return value [' + eventCode + '], outside callback code range');
  }
  if (result < 0 || result >= 2**32) { throw new Error('invalid callback result'); }
  // TODO: table max length check?
  const waitableSetRep = result >> 4;
  return [eventCode, waitableSetRep];
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
  
  fnName;
  target;
  isAsync;
  isManualAsync;
  
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
  
  registerOnStartHandler(f) {
    this.#onStartHandlers.push(f);
  }
  
  onStart(args) {
    _debugLog('[AsyncSubtask#onStart()] args', {
      componentIdx: this.#componentIdx,
      subtaskID: this.#id,
      parentTaskID: this.parentTaskID(),
      fnName: this.fnName,
    });
    
    if (this.#onProgressFn) { this.#onProgressFn(); }
    
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
    this.#childTask?.reject(subtaskErr);
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
    
    if (subtaskValue === null) {
      if (this.#cancelRequested) {
        throw new Error('cancel was not requested, but no value present at return');
      }
      
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
    if (callMetadata && !callMetadata.returnFn && this.isAsync && callMetadata.resultPtr && memory) {
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
      throw new Error('cannot drop subtask before resolve is delivered');
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

function _prepareCall(
memoryIdx,
getMemoryFn,
startFn,
returnFn,
callerComponentIdx,
calleeComponentIdx,
taskReturnTypeIdx,
calleeIsAsyncInt,
stringEncoding,
resultCountOrAsync,
) {
  _debugLog('[_prepareCall()]', {
    memoryIdx,
    callerComponentIdx,
    calleeComponentIdx,
    taskReturnTypeIdx,
    calleeIsAsyncInt,
    stringEncoding,
    resultCountOrAsync,
  });
  const argArray = [...arguments];
  
  // value passed in *may* be as large as u32::MAX which may be mangled into -2
  resultCountOrAsync >>>= 0;
  
  let isAsync = false;
  let hasResultPointer = false;
  if (resultCountOrAsync === 2**32 - 1) {
    // prepare async with no result (u32::MAX)
    isAsync = true;
    hasResultPointer = false;
  } else if (resultCountOrAsync === 2**32 - 2) {
    // prepare async with result (u32::MAX - 1)
    isAsync = true;
    hasResultPointer = true;
  }
  
  const currentCallerTaskMeta = getCurrentTask(callerComponentIdx);
  if (!currentCallerTaskMeta) {
    throw new Error('invalid/missing current task for caller during prepare call');
  }
  
  const currentCallerTask = currentCallerTaskMeta.task;
  if (!currentCallerTask) {
    throw new Error('unexpectedly missing task in meta for caller during prepare call');
  }
  
  if (currentCallerTask.componentIdx() !== callerComponentIdx) {
    throw new Error(`task component idx [${ currentCallerTask.componentIdx() }] !== [${ callerComponentIdx }] (callee ${ calleeComponentIdx })`);
  }
  
  let getCalleeParamsFn;
  let resultPtr = null;
  let directParamsArr;
  if (hasResultPointer) {
    directParamsArr = argArray.slice(10, argArray.length - 1);
    getCalleeParamsFn = () => directParamsArr;
    resultPtr = argArray[argArray.length - 1];
  } else {
    directParamsArr = argArray.slice(10);
    getCalleeParamsFn = () => directParamsArr;
  }
  
  let encoding;
  switch (stringEncoding) {
    case 0:
    encoding = 'utf8';
    break;
    case 1:
    encoding = 'utf16';
    break;
    case 2:
    encoding = 'compact-utf16';
    break;
    default:
    throw new Error(`unrecognized string encoding enum [${stringEncoding}]`);
  }
  
  const subtask = currentCallerTask.createSubtask({
    componentIdx: callerComponentIdx,
    parentTask: currentCallerTask,
    isAsync,
    callMetadata: {
      getMemoryFn,
      memoryIdx,
      resultPtr,
      returnFn,
      startFn,
      stringEncoding,
    }
  });
  
  const [newTask, newTaskID] = createNewCurrentTask({
    componentIdx: calleeComponentIdx,
    isAsync,
    getCalleeParamsFn,
    entryFnName: [
    'task',
    subtask.getParentTask().id(),
    'subtask',
    subtask.id(),
    'new-prepared-async-task'
    ].join('/'),
    stringEncoding,
  });
  newTask.setParentSubtask(subtask);
  newTask.setReturnMemoryIdx(memoryIdx);
  newTask.setReturnMemory(getMemoryFn);
  subtask.setChildTask(newTask);
  
  newTask.subtaskMeta = {
    subtask,
    calleeComponentIdx,
    callerComponentIdx,
    getCalleeParamsFn,
    stringEncoding,
    isAsync,
  };
  
  _setGlobalCurrentTaskMeta({
    taskID: newTask.id(),
    componentIdx: newTask.componentIdx(),
  });
}

function _asyncStartCall(args, callee, paramCount, resultCount, flags) {
  const componentIdx = ASYNC_CURRENT_COMPONENT_IDXS.at(-1);
  
  const globalTaskMeta = _getGlobalCurrentTaskMeta(componentIdx);
  if (!globalTaskMeta) { throw new Error('missing global current task globalTaskMeta'); }
  const taskID = globalTaskMeta.taskID;
  
  _debugLog('[_asyncStartCall()] args', { args, componentIdx });
  const { getCallbackFn, callbackIdx, getPostReturnFn, postReturnIdx } = args;
  
  const preparedTaskMeta = getCurrentTask(componentIdx, taskID);
  if (!preparedTaskMeta) { throw new Error('unexpectedly missing current task'); }
  
  const preparedTask = preparedTaskMeta.task;
  if (!preparedTask) { throw new Error('unexpectedly missing current task'); }
  if (!preparedTask.subtaskMeta) { throw new Error('missing subtask meta from prepare'); }
  
  const {
    subtask,
    returnMemoryIdx,
    getReturnMemoryFn,
    callerComponentIdx,
    calleeComponentIdx,
    getCalleeParamsFn,
    isAsync,
    stringEncoding,
  } = preparedTask.subtaskMeta;
  if (!subtask) { throw new Error("missing subtask from cstate during async start call"); }
  if (calleeComponentIdx !== preparedTask.componentIdx()) {
    throw new Error(`meta callee idx [${calleeComponentIdx}] != current task idx [${preparedTask.componentIdx()}] during async start call`);
  }
  if (calleeComponentIdx !== componentIdx) {
    throw new Error("mismatched componentIdx for async start call (does not match prepare)");
  }
  
  const argArray = [...arguments];
  
  if (resultCount < 0 || resultCount > 1) { throw new Error('invalid/unsupported result count'); }
  
  const callbackFnName = 'callback_' + callbackIdx;
  const callbackFn = getCallbackFn();
  preparedTask.setCallbackFn(callbackFn, callbackFnName);
  preparedTask.setPostReturnFn(getPostReturnFn());
  
  if (resultCount < 0 || resultCount > 1) {
    throw new Error(`unsupported result count [${ resultCount }]`);
  }
  
  const params = preparedTask.getCalleeParams();
  if (paramCount !== params.length) {
    throw new Error(`unexpected callee param count [${ params.length }], _asyncStartCall invocation expected [${ paramCount }]`);
  }
  
  const callerComponentState = getOrCreateAsyncState(subtask.componentIdx());
  
  const calleeComponentState = getOrCreateAsyncState(preparedTask.componentIdx());
  const calleeBackpressure = calleeComponentState.hasBackpressure();
  
  // Set up a handler on subtask completion to lower results from the call into the caller's memory region.
  //
  // NOTE: during fused guest->guest calls this handler is triggered, but does not actually perform
  // lowering manually, as fused modules provider helper functions that can
  subtask.registerOnResolveHandler((res) => {
    _debugLog('[_asyncStartCall()] handling subtask result', { res, subtaskID: subtask.id() });
    
    let subtaskCallMeta = subtask.getCallMetadata();
    
    // NOTE: in the case of guest -> guest async calls, there may be no memory/realloc present,
    // as the host will intermediate the value storage/movement between calls.
    //
    // We can simply take the value and lower it as a parameter
    if (subtaskCallMeta.memory || subtaskCallMeta.realloc) {
      throw new Error("call metadata unexpectedly contains memory/realloc for guest->guest call");
    }
    
    const callerTask = subtask.getParentTask();
    const calleeTask = preparedTask;
    const callerMemoryIdx = callerTask.getReturnMemoryIdx();
    const callerComponentIdx = callerTask.componentIdx();
    
    // If a helper function was provided we are likely in a fused guest->guest call,
    // and the result will be delivered (lift/lowered) via helper function
    if (subtaskCallMeta && subtaskCallMeta.returnFn) {
      _debugLog('[_asyncStartCall()] return function present while handling subtask result, returning early (skipping lower)');
      
      // TODO: centralize calling of returnFn to *one place* (if possible)
      if (subtaskCallMeta.returnFnCalled) { return; }
      
      subtaskCallMeta.returnFn.apply(null, [subtaskCallMeta.resultPtr]);
      return;
    }
    
    // If there is no where to lower the results, exit early
    if (!subtaskCallMeta.resultPtr) {
      _debugLog('[_asyncStartCall()] no result ptr during subtask result handling, returning early (skipping lower)');
      return;
    }
    
    let callerMemory;
    if (callerMemoryIdx !== null && callerMemoryIdx !== undefined) {
      callerMemory = lookupMemoriesForComponent({ componentIdx: callerComponentIdx, memoryIdx: callerMemoryIdx });
    } else {
      const callerMemories = lookupMemoriesForComponent({ componentIdx: callerComponentIdx });
      if (callerMemories.length !== 1) { throw new Error(`unsupported amount of caller memories`); }
      callerMemory = callerMemories[0];
    }
    
    if (!callerMemory) {
      _debugLog('[_asyncStartCall()] missing memory', { subtaskID: subtask.id(), res });
      throw new Error(`missing memory for to guest->guest call result (subtask [${subtask.id()}])`);
    }
    
    const lowerFns = calleeTask.getReturnLowerFns();
    if (!lowerFns || lowerFns.length === 0) {
      _debugLog('[_asyncStartCall()] missing result lower metadata for guest->guest call', { subtaskID: subtask.id() });
      throw new Error(`missing result lower metadata for guest->guest call (subtask [${subtask.id()}])`);
    }
    
    if (lowerFns.length !== 1) {
      _debugLog('[_asyncStartCall()] only single result reportetd for guest->guest call', { subtaskID: subtask.id() });
      throw new Error(`only single result supported for guest->guest calls (subtask [${subtask.id()}])`);
    }
    
    _debugLog('[_asyncStartCall()] lowering results', { subtaskID: subtask.id() });
    lowerFns[0]({
      realloc: undefined,
      memory: callerMemory,
      vals: [res],
      storagePtr: subtaskCallMeta.resultPtr,
      componentIdx: callerComponentIdx,
      stringEncoding: subtaskCallMeta.stringEncoding,
    });
    
  });
  
  subtask.setOnProgressFn(() => {
    subtask.setPendingEvent(() => {
      if (subtask.isResolved()) { subtask.deliverResolve(); }
      const event = {
        code: ASYNC_EVENT_CODE.SUBTASK,
        payload0: subtask.waitableRep(),
        payload1: subtask.getStateNumber(),
      };
      return event;
    });
  });
  
  // Start the (event) driver loop that will resolve the task
  queueMicrotask(async () => {
    let startRes = subtask.onStart({ startFnParams: params });
    startRes = Array.isArray(startRes) ? startRes : [startRes];
    
    await calleeComponentState.suspendTask({
      task: preparedTask,
      readyFn: () => !calleeComponentState.isExclusivelyLocked(),
    });
    
    const started = await preparedTask.enter();
    if (!started) {
      _debugLog('[_asyncStartCall()] task failed early', {
        taskID: preparedTask.id(),
        subtaskID: subtask.id(),
      });
      throw new Error("task failed to start");
      return;
    }
    
    let callbackResult;
    try {
      let jspiCallee = WebAssembly.promising(callee);
      callbackResult = await _withGlobalCurrentTaskMetaAsync({
        taskID: preparedTask.id(),
        componentIdx: preparedTask.componentIdx(),
        fn: () => {
          return jspiCallee.apply(null, startRes);
        }
      });
    } catch(err) {
      _debugLog("[_asyncStartCall()] initial subtask callee run failed", err);
      // NOTE: a good place to rejectt the parent task, if rejection API is enabled
      // subtask.reject(err);
      // subtask.getParentTask().reject(err);
      
      subtask.getParentTask().setErrored(err);
      
      return;
    }
    
    // If there was no callback function, we're dealing with a sync function
    // that was lifted as async without one, there is only the callee.
    if (!callbackFn) {
      _debugLog("[_asyncStartCall()] no callback, resolving w/ callee result", {
        taskID: preparedTask.id(),
        componentIdx: preparedTask.componentIdx(),
        preparedTask,
        stateNumber: preparedTask.taskState(),
        isResolved: preparedTask.isResolved(),
        callbackFn,
      });
      preparedTask.resolve([callbackResult]);
      return;
    }
    
    let fnName = callbackFn.fnName;
    if (!fnName) {
      fnName = [
      '<task ',
      subtask.parentTaskID(),
      '/subtask ',
      subtask.id(),
      '/task ',
      preparedTask.id(),
      '>',
      ].join("");
    }
    
    try {
      _debugLog("[_asyncStartCall()] starting driver loop", {
        fnName,
        componentIdx: preparedTask.componentIdx(),
        subtaskID: subtask.id(),
        childTaskID: subtask.childTaskID(),
        parentTaskID: subtask.parentTaskID(),
      });
      
      await _driverLoop({
        componentState: calleeComponentState,
        task: preparedTask,
        fnName,
        isAsync: true,
        callbackResult,
        resolve,
        reject
      });
    } catch (err) {
      _debugLog("[AsyncStartCall] drive loop call failure", { err });
    }
    
  });
  
  const subtaskState = subtask.getStateNumber();
  if (subtaskState < 0 || subtaskState > 2**5) {
    throw new Error('invalid subtask state, out of valid range');
  }
  
  _debugLog('[_asyncStartCall()] returning subtask rep & state', {
    subtask: {
      rep: subtask.waitableRep(),
      state: subtaskState,
    }
  });
  
  return Number(subtask.waitableRep()) << 4 | subtaskState;
}

function _syncStartCall(callbackIdx) {
  _debugLog('[_syncStartCall()] args', { callbackIdx });
  throw new Error('synchronous start call not implemented!');
}

class Waitable {
  #componentIdx;
  
  #pendingEventFn = null;
  
  #promise;
  #resolve;
  #reject;
  
  #waitableSet = null;
  
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
      });
      if (this.#waitableSet) { this.#waitableSet.removeWaitable(this); }
      if (!waitableSet) {
        this.#waitableSet = null;
        return;
      }
      waitableSet.addWaitable(this);
      this.#waitableSet = waitableSet;
    }
    
    drop() {
      _debugLog('[Waitable#drop()] args', {
        componentIdx: this.#componentIdx,
        waitable: this,
      });
      if (this.hasPendingEvent()) {
        throw new Error('waitables with pending events cannot be dropped');
      }
      this.join(null);
    }
    
  }
  
  const ERR_CTX_TABLES = {};
  
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
  
  const TEXT_DECODER_UTF8 = new TextDecoder();
  const TEXT_ENCODER_UTF8 = new TextEncoder();
  
  function _utf8AllocateAndEncode(s, realloc, memory) {
    if (typeof s !== 'string') {
      throw new TypeError('expected a string, received [' + typeof s + ']');
    }
    if (s.length === 0) { return { ptr: 1, len: 0 }; }
    let buf = TEXT_ENCODER_UTF8.encode(s);
    let ptr = realloc(0, 0, 1, buf.length);
    new Uint8Array(memory.buffer).set(buf, ptr);
    const res = { ptr, len: buf.length, codepoints: [...s].length };
    return res;
  }
  
  
  const T_FLAG = 1 << 30;
  
  function rscTableCreateOwn(table, rep) {
    const free = table[0] & ~T_FLAG;
    if (free === 0) {
      table.push(0);
      table.push(rep | T_FLAG);
      return (table.length >> 1) - 1;
    }
    table[0] = table[free << 1];
    table[free << 1] = 0;
    table[(free << 1) + 1] = rep | T_FLAG;
    return free;
  }
  
  function rscTableRemove(table, handle) {
    const scope = table[handle << 1];
    const val = table[(handle << 1) + 1];
    const own = (val & T_FLAG) !== 0;
    const rep = val & ~T_FLAG;
    if (val === 0 || (scope & T_FLAG) !== 0) {
      throw new TypeError("Invalid handle");
    }
    table[handle << 1] = table[0] | T_FLAG;
    table[0] = handle | T_FLAG;
    return { rep, scope, own };
  }
  
  function createNewCurrentTask(args) {
    _debugLog('[createNewCurrentTask()] args', args);
    const {
      componentIdx,
      isAsync,
      isManualAsync,
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
      entryFnName,
      callbackFn,
      callbackFnName,
      stringEncoding,
      getCalleeParamsFn,
      resultPtr,
      errHandling,
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
  const ASYNC_TASKS_BY_COMPONENT_IDX = new Map();
  
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
    #entryFnName = null;
    
    #onResolveHandlers = [];
    #completionPromise = null;
    #rejected = false;
    
    #exitPromise = null;
    #onExitHandlers = [];
    
    #memoryIdx = null;
    #memory = null;
    
    #callbackFn = null;
    #callbackFnName = null;
    
    #postReturnFn = null;
    
    #getCalleeParamsFn = null;
    
    #stringEncoding = null;
    
    #parentSubtask = null;
    
    #needsExclusiveLock = false;
    
    #errHandling;
    
    #backpressurePromise;
    #backpressureWaiters = 0n;
    
    #returnLowerFns = null;
    
    #subtasks = [];
    
    #entered = false;
    #exited = false;
    #errored = null;
    
    cancelled = false;
    cancelRequested = false;
    alwaysTaskReturn = false;
    
    returnCalls =  0;
    storage = [0, 0];
    borrowedHandles = {};
    
    tmpRetI64HighBits = 0|0;
    
    constructor(opts) {
      this.#id = ++AsyncTask._ID;
      
      if (opts?.componentIdx === undefined) {
        throw new TypeError('missing component id during task creation');
      }
      this.#componentIdx = opts.componentIdx;
      
      this.#state = AsyncTask.State.INITIAL;
      this.#isAsync = opts?.isAsync ?? false;
      this.#isManualAsync = opts?.isManualAsync ?? false;
      this.#entryFnName = opts.entryFnName;
      
      const {
        promise: completionPromise,
        resolve: resolveCompletionPromise,
        reject: rejectCompletionPromise,
      } = promiseWithResolvers();
      this.#completionPromise = completionPromise;
      
      this.#onResolveHandlers.push((results) => {
        if (this.#errored !== null) {
          rejectCompletionPromise(this.#errored);
          return;
        } else if (this.#rejected) {
          rejectCompletionPromise(results);
          return;
        }
        resolveCompletionPromise(results);
      });
      
      const {
        promise: exitPromise,
        resolve: resolveExitPromise,
        reject: rejectExitPromise,
      } = promiseWithResolvers();
      this.#exitPromise = exitPromise;
      
      this.#onExitHandlers.push(() => {
        resolveExitPromise();
      });
      
      if (opts.callbackFn) { this.#callbackFn = opts.callbackFn; }
      if (opts.callbackFnName) { this.#callbackFnName = opts.callbackFnName; }
      
      if (opts.getCalleeParamsFn) { this.#getCalleeParamsFn = opts.getCalleeParamsFn; }
      
      if (opts.stringEncoding) { this.#stringEncoding = opts.stringEncoding; }
      
      if (opts.parentSubtask) { this.#parentSubtask = opts.parentSubtask; }
      
      this.#needsExclusiveLock = this.isSync() || !this.hasCallback();
      
      if (opts.errHandling) { this.#errHandling = opts.errHandling; }
    }
    
    taskState() { return this.#state; }
    id() { return this.#id; }
    componentIdx() { return this.#componentIdx; }
    entryFnName() { return this.#entryFnName; }
    
    completionPromise() { return this.#completionPromise; }
    exitPromise() { return this.#exitPromise; }
    
    isAsync() { return this.#isAsync; }
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
    
    async runCallbackFn(...args) {
      if (!this.#callbackFn) { throw new Error('on callback function has been set for task'); }
      return await this.#callbackFn.apply(null, args);
    }
    
    getCalleeParams() {
      if (!this.#getCalleeParamsFn) { throw new Error('missing/invalid getCalleeParamsFn'); }
      return this.#getCalleeParamsFn();
    }
    
    mayBlock() { return this.isAsync() || this.isResolvedState() }
    
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
        cstate.exclusiveLock();
      }
      return true;
    }
    
    async enter(opts) {
      _debugLog('[AsyncTask#enter()] args', {
        taskID: this.#id,
        componentIdx: this.#componentIdx,
        subtaskID: this.getParentSubtask()?.id(),
      });
      
      if (this.#entered) {
        throw new Error(`task with ID [${this.#id}] should not be entered twice`);
      }
      
      const cstate = getOrCreateAsyncState(this.#componentIdx);
      
      // If a task is either synchronous or host-provided (e.g. a host import, whether sync or async)
      // then we can avoid component-relevant tracking and immediately enter
      if (this.isSync() || opts?.isHost) {
        this.#entered = true;
        
        // TODO(breaking): remove once manually-spccifying async fns is removed
        // It is currently possible for an actually sync export to be specified
        // as async via JSPI
        if (this.#isManualAsync) {
          if (this.needsExclusiveLock()) { cstate.exclusiveLock(); }
        }
        
        return this.#entered;
      }
      
      if (cstate.hasBackpressure()) {
        cstate.addBackpressureWaiter();
        
        const result = await this.waitUntil({
          readyFn: () => !cstate.hasBackpressure(),
          cancellable: true,
        });
        
        cstate.removeBackpressureWaiter();
        
        if (result === AsyncTask.BlockResult.CANCELLED) {
          this.cancel();
          return false;
        }
      }
      
      if (this.needsExclusiveLock()) { cstate.exclusiveLock(); }
      
      this.#entered = true;
      return this.#entered;
    }
    
    isRunningState() { return this.#state !== AsyncTask.State.RESOLVED; }
    isResolvedState() { return this.#state === AsyncTask.State.RESOLVED; }
    isResolved() { return this.#state === AsyncTask.State.RESOLVED; }
    
    async waitUntil(opts) {
      const { readyFn, waitableSetRep, cancellable } = opts;
      _debugLog('[AsyncTask#waitUntil()] args', { taskID: this.#id, waitableSetRep, cancellable });
      
      const state = getOrCreateAsyncState(this.#componentIdx);
      const wset = state.handles.get(waitableSetRep);
      
      let event;
      
      wset.incrementNumWaiting();
      
      const keepGoing = await this.suspendUntil({
        readyFn: () => {
          const hasPendingEvent = wset.hasPendingEvent();
          const ready = readyFn();
          return ready && hasPendingEvent;
        },
        cancellable,
      });
      
      if (keepGoing) {
        event = wset.getPendingEvent();
      } else {
        event = {
          code: ASYNC_EVENT_CODE.TASK_CANCELLED,
          payload0: 0,
          payload1: 0,
        };
      }
      
      wset.decrementNumWaiting();
      
      return event;
    }
    
    async yieldUntil(opts) {
      const { readyFn, cancellable } = opts;
      _debugLog('[AsyncTask#yieldUntil()] args', { taskID: this.#id, cancellable });
      
      const keepGoing = await this.suspendUntil({ readyFn, cancellable });
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
      _debugLog('[AsyncTask#suspendUntil()] args', { cancellable });
      
      const pendingCancelled = this.deliverPendingCancel({ cancellable });
      if (pendingCancelled) { return false; }
      
      const completed = await this.immediateSuspendUntil({ readyFn, cancellable });
      return completed;
    }
    
    // TODO(threads): equivalent to thread.suspend_until()
    async immediateSuspendUntil(opts) {
      const { cancellable, readyFn } = opts;
      _debugLog('[AsyncTask#immediateSuspendUntil()] args', { cancellable, readyFn });
      
      const ready = readyFn();
      if (ready && ASYNC_DETERMINISM === 'random') {
        // const coinFlip = _coinFlip();
        // if (coinFlip) { return true }
        return true;
      }
      
      const keepGoing = await this.immediateSuspend({ cancellable, readyFn });
      return keepGoing;
    }
    
    async immediateSuspend(opts) { // NOTE: equivalent to thread.suspend()
    // TODO(threads): store readyFn on the thread
    const { cancellable, readyFn } = opts;
    _debugLog('[AsyncTask#immediateSuspend()] args', { cancellable, readyFn });
    
    const pendingCancelled = this.deliverPendingCancel({ cancellable });
    if (pendingCancelled) { return false; }
    
    const cstate = getOrCreateAsyncState(this.#componentIdx);
    const keepGoing = await cstate.suspendTask({ task: this, readyFn });
    return keepGoing;
  }
  
  deliverPendingCancel(opts) {
    const { cancellable } = opts;
    _debugLog('[AsyncTask#deliverPendingCancel()] args', { cancellable });
    
    if (cancellable && this.#state === AsyncTask.State.PENDING_CANCEL) {
      this.#state = AsyncTask.State.CANCEL_DELIVERED;
      return true;
    }
    
    return false;
  }
  
  isCancelled() { return this.cancelled }
  
  cancel(args) {
    _debugLog('[AsyncTask#cancel()] args', { });
    if (this.taskState() !== AsyncTask.State.CANCEL_DELIVERED) {
      throw new Error(`(component [${this.#componentIdx}]) task [${this.#id}] invalid task state [${this.taskState()}] for cancellation`);
    }
    if (this.borrowedHandles.length > 0) { throw new Error('task still has borrow handles'); }
    this.cancelled = true;
    this.onResolve(args?.error ?? new Error('task cancelled'));
    this.#state = AsyncTask.State.RESOLVED;
  }
  
  onResolve(taskValue) {
    const handlers = this.#onResolveHandlers;
    this.#onResolveHandlers = [];
    for (const f of handlers) {
      try {
        // TODO(fix): resolve handlers getting called a ton?
        f(taskValue);
      } catch (err) {
        _debugLog("[AsyncTask#onResolve] error during task resolve handler", err);
        throw err;
      }
    }
    
    if (this.#parentSubtask) {
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
        const memory = meta.getMemoryFn();
        meta.returnFn.apply(null, [taskValue, meta.resultPtr]);
        meta.returnFnCalled = true;
      }
    }
    
    if (this.#postReturnFn) {
      _debugLog('[AsyncTask#onResolve()] running post return ', {
        componentIdx: this.#componentIdx,
        taskID: this.#id,
      });
      try {
        this.#postReturnFn(taskValue);
      } catch (err) {
        _debugLog("[AsyncTask#onResolve] error during task resolve handler", err);
        throw err;
      }
    }
    
    if (this.#parentSubtask) {
      this.#parentSubtask.onResolve(taskValue);
    }
  }
  
  registerOnResolveHandler(f) {
    this.#onResolveHandlers.push(f);
  }
  
  isRejected() { return this.#rejected; }
  
  setErrored(err) {
    this.#errored = err;
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
    
    if (this.isResolvedState() || this.#rejected) { return; }
    
    for (const subtask of this.#subtasks) {
      subtask.reject(taskErr);
    }
    
    this.#rejected = true;
    this.cancelRequested = true;
    this.#state = AsyncTask.State.PENDING_CANCEL;
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
      throw new Error(`(component [${this.#componentIdx}]) task [${this.#id}]  is already resolved (did you forget to wait for an import?)`);
    }
    
    if (this.borrowedHandles.length > 0) {
      throw new Error('task still has borrow handles');
    }
    
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
  
  exit() {
    _debugLog('[AsyncTask#exit()]', {
      componentIdx: this.#componentIdx,
      taskID: this.#id,
    });
    
    if (this.#exited)  { throw new Error("task has already exited"); }
    
    if (this.#state !== AsyncTask.State.RESOLVED) {
      // TODO(fix): only fused, manually specified post returns seem to break this invariant,
      // as the TaskReturn trampoline is not activated it seems.
      //
      // see: test/p3/ported/wasmtime/component-async/post-return.js
      //
      // We *should* be able to upgrade this to be more strict and throw at some point,
      // which may involve rewriting the upstream test to surface task return manually somehow.
      //
      //throw new Error(`(component [${this.#componentIdx}]) task [${this.#id}] exited without resolution`);
      _debugLog('[AsyncTask#exit()] task exited without resolution', {
        componentIdx: this.#componentIdx,
        taskID: this.#id,
        subtask: this.getParentSubtask(),
        subtaskID: this.getParentSubtask()?.id(),
      });
      this.#state = AsyncTask.State.RESOLVED;
    }
    
    if (this.borrowedHandles > 0) {
      throw new Error('task [${this.#id}] exited without clearing borrowed handles');
    }
    
    const state = getOrCreateAsyncState(this.#componentIdx);
    if (!state) { throw new Error('missing async state for component [' + this.#componentIdx + ']'); }
    
    // Exempt the host from exclusive lock check
    if (this.#componentIdx !== -1 && this.needsExclusiveLock() && !state.isExclusivelyLocked()) {
      throw new Error(`task [${this.#id}] exit: component [${this.#componentIdx}] should have been exclusively locked`);
    }
    
    state.exclusiveRelease();
    
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
    return !this.#isAsync || this.hasCallback();
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
    waitable.setIdx(cstate.handles.insert(newSubtask));
    waitable.setTarget(`waitable for subtask (waitable id [${waitable.idx()}], subtask internal ID [${newSubtask.id()}])`);
    
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
    if (this.#subtasks.length === 0) { throw new Error('cannot end current subtask: no current subtask'); }
    this.#subtasks = this.#subtasks.filter(t => t !== subtask);
    return subtask;
  }
}

const STREAMS = new RepTable({ target: 'global stream map' });
const ASYNC_STATE = new Map();

function getOrCreateAsyncState(componentIdx, init) {
  if (!ASYNC_STATE.has(componentIdx)) {
    const newState = new ComponentAsyncState({ componentIdx });
    ASYNC_STATE.set(componentIdx, newState);
  }
  return ASYNC_STATE.get(componentIdx);
}

class ComponentAsyncState {
  static EVENT_HANDLER_EVENTS = [ 'backpressure-change' ];
  
  #componentIdx;
  #callingAsyncImport = false;
  #syncImportWait = promiseWithResolvers();
  #locked = false;
  #parkedTasks = new Map();
  #suspendedTasksByTaskID = new Map();
  #suspendedTaskIDs = [];
  #errored = null;
  
  #backpressure = 0;
  #backpressureWaiters = 0n;
  
  #handlerMap = new Map();
  #nextHandlerID = 0n;
  
  #tickLoop = null;
  #tickLoopInterval = null;
  
  #onExclusiveReleaseHandlers = [];
  
  mayLeave = true;
  
  handles;
  subtasks;
  
  constructor(args) {
    this.#componentIdx = args.componentIdx;
    this.handles = new RepTable({ target: `component [${this.#componentIdx}] handles (waitable objects)` });
    this.subtasks = new RepTable({ target: `component [${this.#componentIdx}] subtasks` });
  };
  
  componentIdx() { return this.#componentIdx; }
  
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
    const newValue = Math.max(0, current - 1);
    if (newValue < 0) {
      throw new Error(`invalid new backpressure value [${newValue}], underflow`);
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
  
  isExclusivelyLocked() { return this.#locked === true; }
  setLocked(locked) {
    this.#locked = locked;
  }
  
  // TODO(fix): we might want to check for pre-locked status here, we should be deterministically
  // going from locked -> unlocked and vice versa
  exclusiveLock() {
    _debugLog('[ComponentAsyncState#exclusiveLock()]', {
      locked: this.#locked,
      componentIdx: this.#componentIdx,
    });
    this.setLocked(true);
  }
  
  exclusiveRelease() {
    _debugLog('[ComponentAsyncState#exclusiveRelease()] args', {
      locked: this.#locked,
      componentIdx: this.#componentIdx,
    });
    this.setLocked(false);
    
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
  }
  
  onNextExclusiveRelease(fn) {
    _debugLog('[ComponentAsyncState#()onNextExclusiveRelease] registering');
    this.#onExclusiveReleaseHandlers.push(fn);
  }
  
  #getSuspendedTaskMeta(taskID) {
    return this.#suspendedTasksByTaskID.get(taskID);
  }
  
  #removeSuspendedTaskMeta(taskID) {
    _debugLog('[ComponentAsyncState#removeSuspendedTaskMeta()] removing suspended task', { taskID });
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
    const { task, readyFn } = args;
    const taskID = task.id();
    _debugLog('[ComponentAsyncState#suspendTask()]', {
      taskID,
      componentIdx: this.#componentIdx,
      taskEntryFnName: task.entryFnName(),
      subtask: task.getParentSubtask(),
    });
    
    if (this.#getSuspendedTaskMeta(taskID)) {
      throw new Error(`task [${taskID}] already suspended`);
    }
    
    const { promise, resolve, reject } = promiseWithResolvers();
    this.#addSuspendedTaskMeta({
      task,
      taskID,
      readyFn,
      resume: () => {
        _debugLog('[ComponentAsyncState#suspendTask()] resuming suspended task', { taskID });
        // TODO(threads): it's thread cancellation we should be checking for below, not task
        resolve(!task.isCancelled());
      },
    });
    
    this.runTickLoop();
    
    return promise;
  }
  
  resumeTaskByID(taskID) {
    const meta = this.#removeSuspendedTaskMeta(taskID);
    if (!meta) { return; }
    if (meta.taskID !== taskID) { throw new Error('task ID does not match'); }
    meta.resume();
  }
  
  async runTickLoop() {
    if (this.#tickLoop !== null) { return; }
    this.#tickLoop = 1;
    setTimeout(async () => {
      let done = this.tick();
      while (!done) {
        await new Promise((resolve) => setTimeout(resolve, 30));
        done = this.tick();
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
        _debugLog('[ComponentAsyncState#suspendTask()] detected task rejection, leaving early', { meta });
        this.resumeTaskByID(taskID);
        return;
      }
      
      const isReady = meta.readyFn();
      if (!isReady) { continue; }
      
      this.resumeTaskByID(taskID);
    }
    
    return this.#suspendedTaskIDs.filter(t => t !== null).length === 0;
  }
  
  addStreamEndToTable(args) {
    _debugLog('[ComponentAsyncState#addStreamEnd()] args', args);
    const { tableIdx, streamEnd } = args;
    if (typeof streamEnd === 'number') { throw new Error("INSERTING BAD STREAMEND"); }
    
    let { table, componentIdx } = STREAM_TABLES[tableIdx];
    if (componentIdx === undefined || !table) {
      throw new Error(`invalid global stream table state for table [${tableIdx}]`);
    }
    
    const handle = table.insert(streamEnd);
    streamEnd.setHandle(handle);
    streamEnd.setStreamTableIdx(tableIdx);
    
    const cstate = getOrCreateAsyncState(componentIdx);
    const waitableIdx = cstate.handles.insert(streamEnd);
    streamEnd.setWaitableIdx(waitableIdx);
    
    _debugLog('[ComponentAsyncState#addStreamEnd()] added stream end', {
      tableIdx,
      table,
      handle,
      streamEnd,
      destComponentIdx: componentIdx,
    });
    
    return { handle, waitableIdx };
  }
  
  createWaitable(args) {
    return new Waitable({ target: args?.target, });
  }
  
  createReadableStreamEnd(args) {
    _debugLog('[ComponentAsyncState#createStreamEnd()] args', args);
    const { tableIdx, elemMeta, hostInjectFn } = args;
    
    const { table: localStreamTable, componentIdx } = STREAM_TABLES[tableIdx];
    if (!localStreamTable) {
      throw new Error(`missing global stream table lookup for table [${tableIdx}] while creating stream`);
    }
    if (componentIdx !== this.#componentIdx) {
      throw new Error('component idx mismatch while creating stream');
    }
    
    const waitable = this.createWaitable();
    const streamEnd = new StreamReadableEnd({
      tableIdx,
      elemMeta,
      hostInjectFn,
      pendingBufferMeta: {},
      target: `stream read end (lowered, @init)`,
      waitable,
    });
    
    streamEnd.setWaitableIdx(this.handles.insert(streamEnd));
    streamEnd.setHandle(localStreamTable.insert(streamEnd));
    if (streamEnd.streamTableIdx() !== tableIdx) {
      throw new Error("unexpectedly mismatched stream table");
    }
    const streamEndWaitableIdx = streamEnd.waitableIdx();
    const streamEndHandle = streamEnd.handle();
    waitable.setTarget(`waitable for stream read end (lowered, waitable [${streamEndWaitableIdx}])`);
    streamEnd.setTarget(`stream read end (lowered, waitable [${streamEndWaitableIdx}])`);
    
    return {
      waitableIdx: streamEndWaitableIdx,
      handle: streamEndHandle,
      streamEnd,
    };
  }
  
  createStream(args) {
    _debugLog('[ComponentAsyncState#createStream()] args', args);
    const { tableIdx, elemMeta, hostInjectFn } = args;
    if (tableIdx === undefined) { throw new Error("missing table idx while adding stream"); }
    if (elemMeta === undefined) { throw new Error("missing element metadata while adding stream"); }
    
    const { table: localStreamTable, componentIdx } = STREAM_TABLES[tableIdx];
    if (!localStreamTable) {
      throw new Error(`missing global stream table lookup for table [${tableIdx}] while creating stream`);
    }
    if (componentIdx !== this.#componentIdx) {
      throw new Error('component idx mismatch while creating stream');
    }
    
    const readWaitable = this.createWaitable();
    const writeWaitable = this.createWaitable();
    
    const stream = new InternalStream({
      tableIdx,
      elemMeta,
      readWaitable,
      writeWaitable,
      hostInjectFn,
    });
    stream.setGlobalStreamMapRep(STREAMS.insert(stream));
    
    const writeEnd = stream.writeEnd();
    writeEnd.setWaitableIdx(this.handles.insert(writeEnd));
    writeEnd.setHandle(localStreamTable.insert(writeEnd));
    if (writeEnd.streamTableIdx() !== tableIdx) { throw new Error("unexpectedly mismatched stream table"); }
    
    const writeEndWaitableIdx = writeEnd.waitableIdx();
    const writeEndHandle = writeEnd.handle();
    writeWaitable.setTarget(`waitable for stream write end (waitable [${writeEndWaitableIdx}])`);
    writeEnd.setTarget(`stream write end (waitable [${writeEndWaitableIdx}])`);
    
    const readEnd = stream.readEnd();
    readEnd.setWaitableIdx(this.handles.insert(readEnd));
    readEnd.setHandle(localStreamTable.insert(readEnd));
    if (readEnd.streamTableIdx() !== tableIdx) { throw new Error("unexpectedly mismatched stream table"); }
    
    const readEndWaitableIdx = readEnd.waitableIdx();
    const readEndHandle = readEnd.handle();
    readWaitable.setTarget(`waitable for read end (waitable [${readEndWaitableIdx}])`);
    readEnd.setTarget(`stream read end (waitable [${readEndWaitableIdx}])`);
    
    return {
      writeEnd,
      writeEndWaitableIdx,
      writeEndHandle,
      readEndWaitableIdx,
      readEndHandle,
      readEnd,
    };
  }
  
  getStreamEnd(args) {
    _debugLog('[ComponentAsyncState#getStreamEnd()] args', args);
    const { tableIdx, streamEndHandle, streamEndWaitableIdx } = args;
    if (tableIdx === undefined) {
      throw new Error('missing table idx while getting stream end');
    }
    
    const { table, componentIdx } = STREAM_TABLES[tableIdx];
    const cstate = getOrCreateAsyncState(componentIdx);
    
    let streamEnd;
    if (streamEndWaitableIdx !== undefined) {
      streamEnd = cstate.handles.get(streamEndWaitableIdx);
    } else if (streamEndHandle !== undefined) {
      if (!table) { throw new Error(`missing/invalid table [${tableIdx}] while getting stream end`); }
      streamEnd = table.get(streamEndHandle);
    } else {
      throw new TypeError("must specify either waitable idx or handle to retrieve stream");
    }
    
    if (!streamEnd) {
      throw new Error(`missing stream end (tableIdx [${tableIdx}], handle [${streamEndHandle}], waitableIdx [${streamEndWaitableIdx}])`);
    }
    if (tableIdx && streamEnd.streamTableIdx() !== tableIdx) {
      throw new Error(`stream end table idx [${streamEnd.streamTableIdx()}] does not match [${tableIdx}]`);
    }
    
    return streamEnd;
  }
  
  deleteStreamEnd(args) {
    _debugLog('[ComponentAsyncState#deleteStreamEnd()] args', args);
    const { tableIdx, streamEndWaitableIdx } = args;
    if (tableIdx === undefined) { throw new Error("missing table idx while removing stream end"); }
    if (streamEndWaitableIdx === undefined) { throw new Error("missing stream idx while removing stream end"); }
    
    const { table, componentIdx } = STREAM_TABLES[tableIdx];
    const cstate = getOrCreateAsyncState(componentIdx);
    
    const streamEnd = cstate.handles.get(streamEndWaitableIdx);
    if (!streamEnd) {
      throw new Error(`missing stream end [${streamEndWaitableIdx}] in component handles while deleting stream`);
    }
    if (streamEnd.streamTableIdx() !== tableIdx) {
      throw new Error(`stream end table idx [${streamEnd.streamTableIdx()}] does not match [${tableIdx}]`);
    }
    
    let removed = cstate.handles.remove(streamEnd.waitableIdx());
    if (!removed) {
      throw new Error(`failed to remove stream end [${streamEndWaitableIdx}] waitable obj in component [${componentIdx}]`);
    }
    
    removed = table.remove(streamEnd.handle());
    if (!removed) {
      throw new Error(`failed to remove stream end with handle [${streamEnd.handle()}] from stream table [${tableIdx}] in component [${componentIdx}]`);
    }
    
    return streamEnd;
  }
  
  removeStreamEndFromTable(args) {
    _debugLog('[ComponentAsyncState#removeStreamEndFromTable()] args', args);
    
    const { tableIdx, streamWaitableIdx } = args;
    if (tableIdx === undefined) { throw new Error("missing table idx while removing stream end"); }
    if (streamWaitableIdx === undefined) {
      throw new Error("missing stream end waitable idx while removing stream end");
    }
    
    const { table, componentIdx } = STREAM_TABLES[tableIdx];
    if (!table) { throw new Error(`missing/invalid table [${tableIdx}] while removing stream end`); }
    
    const cstate = getOrCreateAsyncState(componentIdx);
    
    const streamEnd = cstate.handles.get(streamWaitableIdx);
    if (!streamEnd) {
      throw new Error(`missing stream end (handle [${streamWaitableIdx}], table [${tableIdx}])`);
    }
    const handle = streamEnd.handle();
    
    let removed = cstate.handles.remove(streamWaitableIdx);
    if (!removed) {
      throw new Error(`failed to remove streamEnd from handles (waitable idx [${streamWaitableIdx}]), component [${componentIdx}])`);
    }
    
    removed = table.remove(handle);
    if (!removed) {
      throw new Error(`failed to remove streamEnd from table (handle [${handle}]), table [${tableIdx}], component [${componentIdx}])`);
    }
    
    return streamEnd;
  }
  
  createFuture(args) {
    _debugLog('[ComponentAsyncState#createFuture()] args', args);
    const { tableIdx, elemMeta, hostInjectFn } = args;
    if (tableIdx === undefined) { throw new Error("missing table idx while adding future"); }
    if (elemMeta === undefined) { throw new Error("missing element metadata while adding future"); }
    
    const { table: futureTable, componentIdx } = FUTURE_TABLES[tableIdx];
    if (!futureTable) {
      throw new Error(`missing global future table lookup for table [${tableIdx}] while creating future`);
    }
    if (componentIdx !== this.#componentIdx) {
      throw new Error('component idx mismatch while creating future');
    }
    
    const readWaitable = this.createWaitable();
    const writeWaitable = this.createWaitable();
    
    const future = new InternalFuture({
      tableIdx,
      componentIdx: this.#componentIdx,
      elemMeta,
      readWaitable,
      writeWaitable,
      hostInjectFn,
    });
    future.setGlobalFutureMapRep(FUTURES.insert(future));
    
    const writeEnd = future.writeEnd();
    writeEnd.setWaitableIdx(this.handles.insert(writeEnd));
    writeEnd.setHandle(futureTable.insert(writeEnd));
    if (writeEnd.futureTableIdx() !== tableIdx) { throw new Error("unexpectedly mismatched future table"); }
    
    const writeEndWaitableIdx = writeEnd.waitableIdx();
    const writeEndHandle = writeEnd.handle();
    writeWaitable.setTarget(`waitable for future write end (waitable [${writeEndWaitableIdx}])`);
    writeEnd.setTarget(`future write end (waitable [${writeEndWaitableIdx}])`);
    
    const readEnd = future.readEnd();
    readEnd.setWaitableIdx(this.handles.insert(readEnd));
    readEnd.setHandle(futureTable.insert(readEnd));
    if (readEnd.futureTableIdx() !== tableIdx) { throw new Error("unexpectedly mismatched future table"); }
    
    const readEndWaitableIdx = readEnd.waitableIdx();
    const readEndHandle = readEnd.handle();
    readWaitable.setTarget(`waitable for read end (waitable [${readEndWaitableIdx}])`);
    readEnd.setTarget(`future read end (waitable [${readEndWaitableIdx}])`);
    
    return {
      writeEnd,
      writeEndWaitableIdx,
      writeEndHandle,
      readEndWaitableIdx,
      readEndHandle,
      readEnd,
    };
  }
  
  getFutureEnd(args) {
    _debugLog('[ComponentAsyncState#getFutureEnd()] args', args);
    const { tableIdx, futureEndHandle, futureEndWaitableIdx } = args;
    if (tableIdx === undefined) {
      throw new Error('missing table idx while getting future end');
    }
    
    const { table, componentIdx } = FUTURE_TABLES[tableIdx];
    const cstate = getOrCreateAsyncState(componentIdx);
    
    let futureEnd;
    if (futureEndWaitableIdx !== undefined) {
      futureEnd = cstate.handles.get(futureEndWaitableIdx);
    } else if (futureEndHandle !== undefined) {
      if (!table) { throw new Error(`missing/invalid table [${tableIdx}] while getting future end`); }
      futureEnd = table.get(futureEndHandle);
    } else {
      throw new TypeError("must specify either waitable idx or handle to retrieve future");
    }
    
    if (!futureEnd) {
      throw new Error(`missing future end (tableIdx [${tableIdx}], handle [${futureEndHandle}], waitableIdx [${futureEndWaitableIdx}])`);
    }
    if (tableIdx && futureEnd.futureTableIdx() !== tableIdx) {
      throw new Error(`future end table idx [${futureEnd.futureTableIdx()}] does not match [${tableIdx}]`);
    }
    
    return futureEnd;
  }
  
  removeFutureEndFromTable(args) {
    _debugLog('[ComponentAsyncState#removeFutureEndFromTable()] args', args);
    
    const { tableIdx, futureWaitableIdx } = args;
    if (tableIdx === undefined) { throw new Error("missing table idx while removing future end"); }
    if (futureWaitableIdx === undefined) {
      throw new Error("missing future end waitable idx while removing future end");
    }
    
    const { table, componentIdx } = FUTURE_TABLES[tableIdx];
    if (!table) { throw new Error(`missing/invalid table [${tableIdx}] while removing future end`); }
    
    const cstate = getOrCreateAsyncState(componentIdx);
    
    const futureEnd = cstate.handles.get(futureWaitableIdx);
    if (!futureEnd) {
      throw new Error(`missing future end (handle [${futureWaitableIdx}], table [${tableIdx}])`);
    }
    const handle = futureEnd.handle();
    
    let removed = cstate.handles.remove(futureWaitableIdx);
    if (!removed) {
      throw new Error(`failed to remove futureEnd from handles (waitable idx [${futureWaitableIdx}]), component [${componentIdx}])`);
    }
    
    removed = table.remove(handle);
    if (!removed) {
      throw new Error(`failed to remove futureEnd from table (handle [${handle}]), table [${tableIdx}], component [${componentIdx}])`);
    }
    
    return futureEnd;
  }
  
}

const base64Compile = str => WebAssembly.compile(typeof Buffer !== 'undefined' ? Buffer.from(str, 'base64') : Uint8Array.from(atob(str), b => b.charCodeAt(0)));

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

const handleTables = [];

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

const isLE = new Uint8Array(new Uint16Array([1]).buffer)[0] === 1;

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
let exports1SerializeInst;

function serializeInst(arg0) {
  
  var encodeRes = _utf8AllocateAndEncode(arg0, realloc0, memory0);
  var ptr0= encodeRes.ptr;
  var len0 = encodeRes.len;
  
  _debugLog('[iface="serialize-inst", function="serialize-inst"][Instruction::CallWasm] enter', {
    funcName: 'serialize-inst',
    paramCount: 2,
    async: false,
    postReturn: true,
  });
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'exports1SerializeInst',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'none',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => exports1SerializeInst(ptr0, len0),
  });
  
  var ptr1 = dataView(memory0).getUint32(ret + 0, true);
  var len1 = dataView(memory0).getUint32(ret + 4, true);
  var result1 = new Uint8Array(memory0.buffer.slice(ptr1, ptr1 + len1 * 1));
  _debugLog('[iface="serialize-inst", function="serialize-inst"][Instruction::Return]', {
    funcName: 'serialize-inst',
    paramCount: 1,
    async: false,
    postReturn: true
  });
  task.resolve([result1]);
  const retCopy = result1;
  
  let cstate = getOrCreateAsyncState(0);
  cstate.mayLeave = false;
  postReturn0(ret);
  cstate.mayLeave = true;
  task.exit();
  return retCopy;
  
}
let exports1DeserializeInst;

function deserializeInst(arg0) {
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
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'exports1DeserializeInst',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'none',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => exports1DeserializeInst(ptr0, len0),
  });
  
  var ptr1 = dataView(memory0).getUint32(ret + 0, true);
  var len1 = dataView(memory0).getUint32(ret + 4, true);
  var result1 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr1, len1));
  _debugLog('[iface="deserialize-inst", function="deserialize-inst"][Instruction::Return]', {
    funcName: 'deserialize-inst',
    paramCount: 1,
    async: false,
    postReturn: true
  });
  task.resolve([result1]);
  const retCopy = result1;
  
  let cstate = getOrCreateAsyncState(0);
  cstate.mayLeave = false;
  postReturn0(ret);
  cstate.mayLeave = true;
  task.exit();
  return retCopy;
  
}
let exports1SerializeOpReturnData;

function serializeOpReturnData(arg0) {
  
  var encodeRes = _utf8AllocateAndEncode(arg0, realloc0, memory0);
  var ptr0= encodeRes.ptr;
  var len0 = encodeRes.len;
  
  _debugLog('[iface="serialize-op-return-data", function="serialize-op-return-data"][Instruction::CallWasm] enter', {
    funcName: 'serialize-op-return-data',
    paramCount: 2,
    async: false,
    postReturn: true,
  });
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'exports1SerializeOpReturnData',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'none',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => exports1SerializeOpReturnData(ptr0, len0),
  });
  
  var ptr1 = dataView(memory0).getUint32(ret + 0, true);
  var len1 = dataView(memory0).getUint32(ret + 4, true);
  var result1 = new Uint8Array(memory0.buffer.slice(ptr1, ptr1 + len1 * 1));
  _debugLog('[iface="serialize-op-return-data", function="serialize-op-return-data"][Instruction::Return]', {
    funcName: 'serialize-op-return-data',
    paramCount: 1,
    async: false,
    postReturn: true
  });
  task.resolve([result1]);
  const retCopy = result1;
  
  let cstate = getOrCreateAsyncState(0);
  cstate.mayLeave = false;
  postReturn0(ret);
  cstate.mayLeave = true;
  task.exit();
  return retCopy;
  
}
let exports1DeserializeOpReturnData;

function deserializeOpReturnData(arg0) {
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
  
  _debugLog('[iface="deserialize-op-return-data", function="deserialize-op-return-data"][Instruction::CallWasm] enter', {
    funcName: 'deserialize-op-return-data',
    paramCount: 2,
    async: false,
    postReturn: true,
  });
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'exports1DeserializeOpReturnData',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'none',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => exports1DeserializeOpReturnData(ptr0, len0),
  });
  
  var ptr1 = dataView(memory0).getUint32(ret + 0, true);
  var len1 = dataView(memory0).getUint32(ret + 4, true);
  var result1 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr1, len1));
  _debugLog('[iface="deserialize-op-return-data", function="deserialize-op-return-data"][Instruction::Return]', {
    funcName: 'deserialize-op-return-data',
    paramCount: 1,
    async: false,
    postReturn: true
  });
  task.resolve([result1]);
  const retCopy = result1;
  
  let cstate = getOrCreateAsyncState(0);
  cstate.mayLeave = false;
  postReturn0(ret);
  cstate.mayLeave = true;
  task.exit();
  return retCopy;
  
}
let exports1ValidateWit;

function validateWit(arg0) {
  
  var encodeRes = _utf8AllocateAndEncode(arg0, realloc0, memory0);
  var ptr0= encodeRes.ptr;
  var len0 = encodeRes.len;
  
  _debugLog('[iface="validate-wit", function="validate-wit"][Instruction::CallWasm] enter', {
    funcName: 'validate-wit',
    paramCount: 2,
    async: false,
    postReturn: true,
  });
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'exports1ValidateWit',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'none',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => exports1ValidateWit(ptr0, len0),
  });
  
  let variant5;
  switch (dataView(memory0).getUint8(ret + 0, true)) {
    case 0: {
      variant5= {
        tag: 'ok',
      };
      break;
    }
    case 1: {
      var ptr1 = dataView(memory0).getUint32(ret + 4, true);
      var len1 = dataView(memory0).getUint32(ret + 8, true);
      var result1 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr1, len1));
      variant5= {
        tag: 'parse-error',
        val: result1
      };
      break;
    }
    case 2: {
      var len4 = dataView(memory0).getUint32(ret + 8, true);
      var base4 = dataView(memory0).getUint32(ret + 4, true);
      var result4 = [];
      for (let i = 0; i < len4; i++) {
        const base = base4 + i * 16;
        var ptr2 = dataView(memory0).getUint32(base + 0, true);
        var len2 = dataView(memory0).getUint32(base + 4, true);
        var result2 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr2, len2));
        var ptr3 = dataView(memory0).getUint32(base + 8, true);
        var len3 = dataView(memory0).getUint32(base + 12, true);
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
  postReturn1(ret);
  cstate.mayLeave = true;
  task.exit();
  return retCopy;
  
}
const handleTable0 = [T_FLAG, 0];
const finalizationRegistry0 = finalizationRegistryCreate((handle) => {
  const { rep } = rscTableRemove(handleTable0, handle);
  exports0['0'](rep);
});

handleTables[0] = handleTable0;
let witCodecConstructorWit;

class Wit{
  constructor(arg0) {
    
    var encodeRes = _utf8AllocateAndEncode(arg0, realloc0, memory0);
    var ptr0= encodeRes.ptr;
    var len0 = encodeRes.len;
    
    _debugLog('[iface="root:component/wit-codec", function="[constructor]wit"][Instruction::CallWasm] enter', {
      funcName: '[constructor]wit',
      paramCount: 2,
      async: false,
      postReturn: false,
    });
    const hostProvided = false;
    
    const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
      componentIdx: 0,
      isAsync: false,
      isManualAsync: false,
      entryFnName: 'witCodecConstructorWit',
      getCallbackFn: () => null,
      callbackFnName: 'null',
      errHandling: 'none',
      callingWasmExport: true,
    });
    
    const started = task.enterSync();
    task.setReturnMemoryIdx(0);
    task.setReturnMemory(memory0);
    let ret =   _withGlobalCurrentTaskMeta({
      taskID: task.id(),
      componentIdx: task.componentIdx(),
      fn: () => witCodecConstructorWit(ptr0, len0),
    });
    
    var handle2 = ret;
    var rsc1 = new.target === Wit ? this : Object.create(Wit.prototype);
    Object.defineProperty(rsc1, symbolRscHandle, { writable: true, value: handle2});
    finalizationRegistry0.register(rsc1, handle2, rsc1);
    Object.defineProperty(rsc1, symbolDispose, { writable: true, value: function () {
      finalizationRegistry0.unregister(rsc1);
      rscTableRemove(handleTable0, handle2);
      rsc1[symbolDispose] = emptyFunc;
      rsc1[symbolRscHandle] = undefined;
      exports0['0'](handleTable0[(handle2 << 1) + 1] & ~T_FLAG);
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
  }
}
let witCodecMethodWitEncodeCall;

Wit.prototype.encodeCall = function encodeCall(arg1, arg2) {
  
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
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'witCodecMethodWitEncodeCall',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => witCodecMethodWitEncodeCall(handle0, ptr2, len2, ptr3, len3),
  });
  
  let variant6;
  switch (dataView(memory0).getUint8(ret + 0, true)) {
    case 0: {
      var ptr4 = dataView(memory0).getUint32(ret + 4, true);
      var len4 = dataView(memory0).getUint32(ret + 8, true);
      var result4 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr4, len4));
      variant6= {
        tag: 'ok',
        val: result4
      };
      break;
    }
    case 1: {
      var ptr5 = dataView(memory0).getUint32(ret + 4, true);
      var len5 = dataView(memory0).getUint32(ret + 8, true);
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
  postReturn2(ret);
  cstate.mayLeave = true;
  task.exit();
  
  
  
  if (typeof retCopy === 'object' && retCopy.tag === 'err') {
    throw new ComponentError(retCopy.val);
  }
  return retCopy.val;
  
};
let witCodecMethodWitDecodeResult;

Wit.prototype.decodeResult = function decodeResult(arg1, arg2) {
  
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
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'witCodecMethodWitDecodeResult',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => witCodecMethodWitDecodeResult(handle0, ptr2, len2, ptr3, len3),
  });
  
  let variant6;
  switch (dataView(memory0).getUint8(ret + 0, true)) {
    case 0: {
      var ptr4 = dataView(memory0).getUint32(ret + 4, true);
      var len4 = dataView(memory0).getUint32(ret + 8, true);
      var result4 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr4, len4));
      variant6= {
        tag: 'ok',
        val: result4
      };
      break;
    }
    case 1: {
      var ptr5 = dataView(memory0).getUint32(ret + 4, true);
      var len5 = dataView(memory0).getUint32(ret + 8, true);
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
  postReturn2(ret);
  cstate.mayLeave = true;
  task.exit();
  
  
  
  if (typeof retCopy === 'object' && retCopy.tag === 'err') {
    throw new ComponentError(retCopy.val);
  }
  return retCopy.val;
  
};
let witCodecMethodWitParse;

Wit.prototype.parse = function parse() {
  
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
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'witCodecMethodWitParse',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => witCodecMethodWitParse(handle0),
  });
  
  let variant4;
  switch (dataView(memory0).getUint8(ret + 0, true)) {
    case 0: {
      var ptr2 = dataView(memory0).getUint32(ret + 4, true);
      var len2 = dataView(memory0).getUint32(ret + 8, true);
      var result2 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr2, len2));
      variant4= {
        tag: 'ok',
        val: result2
      };
      break;
    }
    case 1: {
      var ptr3 = dataView(memory0).getUint32(ret + 4, true);
      var len3 = dataView(memory0).getUint32(ret + 8, true);
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
  postReturn2(ret);
  cstate.mayLeave = true;
  task.exit();
  
  
  
  if (typeof retCopy === 'object' && retCopy.tag === 'err') {
    throw new ComponentError(retCopy.val);
  }
  return retCopy.val;
  
};
let numericsU64ToInteger;

function u64ToInteger(arg0) {
  _debugLog('[iface="root:component/numerics", function="u64-to-integer"][Instruction::CallWasm] enter', {
    funcName: 'u64-to-integer',
    paramCount: 1,
    async: false,
    postReturn: false,
  });
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'numericsU64ToInteger',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'none',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => numericsU64ToInteger(toUint64(arg0)),
  });
  
  let enum0;
  switch (dataView(memory0).getUint8(ret + 32, true)) {
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
    r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 0, true))),
    r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 8, true))),
    r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 16, true))),
    r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 24, true))),
    sign: enum0,
  }]);
  task.exit();
  return {
    r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 0, true))),
    r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 8, true))),
    r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 16, true))),
    r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 24, true))),
    sign: enum0,
  };
}
let numericsS64ToInteger;

function s64ToInteger(arg0) {
  _debugLog('[iface="root:component/numerics", function="s64-to-integer"][Instruction::CallWasm] enter', {
    funcName: 's64-to-integer',
    paramCount: 1,
    async: false,
    postReturn: false,
  });
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'numericsS64ToInteger',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'none',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => numericsS64ToInteger(toInt64(arg0)),
  });
  
  let enum0;
  switch (dataView(memory0).getUint8(ret + 32, true)) {
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
    r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 0, true))),
    r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 8, true))),
    r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 16, true))),
    r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 24, true))),
    sign: enum0,
  }]);
  task.exit();
  return {
    r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 0, true))),
    r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 8, true))),
    r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 16, true))),
    r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 24, true))),
    sign: enum0,
  };
}
let numericsStringToInteger;

function stringToInteger(arg0) {
  
  var encodeRes = _utf8AllocateAndEncode(arg0, realloc0, memory0);
  var ptr0= encodeRes.ptr;
  var len0 = encodeRes.len;
  
  _debugLog('[iface="root:component/numerics", function="string-to-integer"][Instruction::CallWasm] enter', {
    funcName: 'string-to-integer',
    paramCount: 2,
    async: false,
    postReturn: true,
  });
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'numericsStringToInteger',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => numericsStringToInteger(ptr0, len0),
  });
  
  let variant8;
  switch (dataView(memory0).getUint8(ret + 0, true)) {
    case 0: {
      let enum1;
      switch (dataView(memory0).getUint8(ret + 40, true)) {
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
          r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 8, true))),
          r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 16, true))),
          r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 24, true))),
          r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 32, true))),
          sign: enum1,
        }
      };
      break;
    }
    case 1: {
      let variant7;
      switch (dataView(memory0).getUint8(ret + 8, true)) {
        case 0: {
          var ptr2 = dataView(memory0).getUint32(ret + 12, true);
          var len2 = dataView(memory0).getUint32(ret + 16, true);
          var result2 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr2, len2));
          variant7= {
            tag: 'message',
            val: result2
          };
          break;
        }
        case 1: {
          var ptr3 = dataView(memory0).getUint32(ret + 12, true);
          var len3 = dataView(memory0).getUint32(ret + 16, true);
          var result3 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr3, len3));
          variant7= {
            tag: 'overflow',
            val: result3
          };
          break;
        }
        case 2: {
          var ptr4 = dataView(memory0).getUint32(ret + 12, true);
          var len4 = dataView(memory0).getUint32(ret + 16, true);
          var result4 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr4, len4));
          variant7= {
            tag: 'div-by-zero',
            val: result4
          };
          break;
        }
        case 3: {
          var ptr5 = dataView(memory0).getUint32(ret + 12, true);
          var len5 = dataView(memory0).getUint32(ret + 16, true);
          var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
          variant7= {
            tag: 'syntax',
            val: result5
          };
          break;
        }
        case 4: {
          var ptr6 = dataView(memory0).getUint32(ret + 12, true);
          var len6 = dataView(memory0).getUint32(ret + 16, true);
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
  
}
let numericsIntegerToString;

function integerToString(arg0) {
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
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'numericsIntegerToString',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'none',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => numericsIntegerToString(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1),
  });
  
  var ptr2 = dataView(memory0).getUint32(ret + 0, true);
  var len2 = dataView(memory0).getUint32(ret + 4, true);
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
  postReturn0(ret);
  cstate.mayLeave = true;
  task.exit();
  return retCopy;
  
}
let numericsEqInteger;

function eqInteger(arg0, arg1) {
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
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'numericsEqInteger',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'none',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => numericsEqInteger(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1, toUint64(v2_0), toUint64(v2_1), toUint64(v2_2), toUint64(v2_3), enum3),
  });
  
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
}
let numericsCmpInteger;

function cmpInteger(arg0, arg1) {
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
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'numericsCmpInteger',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'none',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => numericsCmpInteger(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1, toUint64(v2_0), toUint64(v2_1), toUint64(v2_2), toUint64(v2_3), enum3),
  });
  
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
}
let numericsAddInteger;

function addInteger(arg0, arg1) {
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
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'numericsAddInteger',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => numericsAddInteger(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1, toUint64(v2_0), toUint64(v2_1), toUint64(v2_2), toUint64(v2_3), enum3),
  });
  
  let variant11;
  switch (dataView(memory0).getUint8(ret + 0, true)) {
    case 0: {
      let enum4;
      switch (dataView(memory0).getUint8(ret + 40, true)) {
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
          r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 8, true))),
          r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 16, true))),
          r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 24, true))),
          r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 32, true))),
          sign: enum4,
        }
      };
      break;
    }
    case 1: {
      let variant10;
      switch (dataView(memory0).getUint8(ret + 8, true)) {
        case 0: {
          var ptr5 = dataView(memory0).getUint32(ret + 12, true);
          var len5 = dataView(memory0).getUint32(ret + 16, true);
          var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
          variant10= {
            tag: 'message',
            val: result5
          };
          break;
        }
        case 1: {
          var ptr6 = dataView(memory0).getUint32(ret + 12, true);
          var len6 = dataView(memory0).getUint32(ret + 16, true);
          var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
          variant10= {
            tag: 'overflow',
            val: result6
          };
          break;
        }
        case 2: {
          var ptr7 = dataView(memory0).getUint32(ret + 12, true);
          var len7 = dataView(memory0).getUint32(ret + 16, true);
          var result7 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr7, len7));
          variant10= {
            tag: 'div-by-zero',
            val: result7
          };
          break;
        }
        case 3: {
          var ptr8 = dataView(memory0).getUint32(ret + 12, true);
          var len8 = dataView(memory0).getUint32(ret + 16, true);
          var result8 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr8, len8));
          variant10= {
            tag: 'syntax',
            val: result8
          };
          break;
        }
        case 4: {
          var ptr9 = dataView(memory0).getUint32(ret + 12, true);
          var len9 = dataView(memory0).getUint32(ret + 16, true);
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
  
}
let numericsSubInteger;

function subInteger(arg0, arg1) {
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
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'numericsSubInteger',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => numericsSubInteger(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1, toUint64(v2_0), toUint64(v2_1), toUint64(v2_2), toUint64(v2_3), enum3),
  });
  
  let variant11;
  switch (dataView(memory0).getUint8(ret + 0, true)) {
    case 0: {
      let enum4;
      switch (dataView(memory0).getUint8(ret + 40, true)) {
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
          r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 8, true))),
          r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 16, true))),
          r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 24, true))),
          r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 32, true))),
          sign: enum4,
        }
      };
      break;
    }
    case 1: {
      let variant10;
      switch (dataView(memory0).getUint8(ret + 8, true)) {
        case 0: {
          var ptr5 = dataView(memory0).getUint32(ret + 12, true);
          var len5 = dataView(memory0).getUint32(ret + 16, true);
          var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
          variant10= {
            tag: 'message',
            val: result5
          };
          break;
        }
        case 1: {
          var ptr6 = dataView(memory0).getUint32(ret + 12, true);
          var len6 = dataView(memory0).getUint32(ret + 16, true);
          var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
          variant10= {
            tag: 'overflow',
            val: result6
          };
          break;
        }
        case 2: {
          var ptr7 = dataView(memory0).getUint32(ret + 12, true);
          var len7 = dataView(memory0).getUint32(ret + 16, true);
          var result7 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr7, len7));
          variant10= {
            tag: 'div-by-zero',
            val: result7
          };
          break;
        }
        case 3: {
          var ptr8 = dataView(memory0).getUint32(ret + 12, true);
          var len8 = dataView(memory0).getUint32(ret + 16, true);
          var result8 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr8, len8));
          variant10= {
            tag: 'syntax',
            val: result8
          };
          break;
        }
        case 4: {
          var ptr9 = dataView(memory0).getUint32(ret + 12, true);
          var len9 = dataView(memory0).getUint32(ret + 16, true);
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
  
}
let numericsMulInteger;

function mulInteger(arg0, arg1) {
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
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'numericsMulInteger',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => numericsMulInteger(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1, toUint64(v2_0), toUint64(v2_1), toUint64(v2_2), toUint64(v2_3), enum3),
  });
  
  let variant11;
  switch (dataView(memory0).getUint8(ret + 0, true)) {
    case 0: {
      let enum4;
      switch (dataView(memory0).getUint8(ret + 40, true)) {
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
          r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 8, true))),
          r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 16, true))),
          r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 24, true))),
          r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 32, true))),
          sign: enum4,
        }
      };
      break;
    }
    case 1: {
      let variant10;
      switch (dataView(memory0).getUint8(ret + 8, true)) {
        case 0: {
          var ptr5 = dataView(memory0).getUint32(ret + 12, true);
          var len5 = dataView(memory0).getUint32(ret + 16, true);
          var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
          variant10= {
            tag: 'message',
            val: result5
          };
          break;
        }
        case 1: {
          var ptr6 = dataView(memory0).getUint32(ret + 12, true);
          var len6 = dataView(memory0).getUint32(ret + 16, true);
          var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
          variant10= {
            tag: 'overflow',
            val: result6
          };
          break;
        }
        case 2: {
          var ptr7 = dataView(memory0).getUint32(ret + 12, true);
          var len7 = dataView(memory0).getUint32(ret + 16, true);
          var result7 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr7, len7));
          variant10= {
            tag: 'div-by-zero',
            val: result7
          };
          break;
        }
        case 3: {
          var ptr8 = dataView(memory0).getUint32(ret + 12, true);
          var len8 = dataView(memory0).getUint32(ret + 16, true);
          var result8 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr8, len8));
          variant10= {
            tag: 'syntax',
            val: result8
          };
          break;
        }
        case 4: {
          var ptr9 = dataView(memory0).getUint32(ret + 12, true);
          var len9 = dataView(memory0).getUint32(ret + 16, true);
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
  
}
let numericsDivInteger;

function divInteger(arg0, arg1) {
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
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'numericsDivInteger',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => numericsDivInteger(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1, toUint64(v2_0), toUint64(v2_1), toUint64(v2_2), toUint64(v2_3), enum3),
  });
  
  let variant11;
  switch (dataView(memory0).getUint8(ret + 0, true)) {
    case 0: {
      let enum4;
      switch (dataView(memory0).getUint8(ret + 40, true)) {
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
          r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 8, true))),
          r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 16, true))),
          r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 24, true))),
          r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 32, true))),
          sign: enum4,
        }
      };
      break;
    }
    case 1: {
      let variant10;
      switch (dataView(memory0).getUint8(ret + 8, true)) {
        case 0: {
          var ptr5 = dataView(memory0).getUint32(ret + 12, true);
          var len5 = dataView(memory0).getUint32(ret + 16, true);
          var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
          variant10= {
            tag: 'message',
            val: result5
          };
          break;
        }
        case 1: {
          var ptr6 = dataView(memory0).getUint32(ret + 12, true);
          var len6 = dataView(memory0).getUint32(ret + 16, true);
          var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
          variant10= {
            tag: 'overflow',
            val: result6
          };
          break;
        }
        case 2: {
          var ptr7 = dataView(memory0).getUint32(ret + 12, true);
          var len7 = dataView(memory0).getUint32(ret + 16, true);
          var result7 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr7, len7));
          variant10= {
            tag: 'div-by-zero',
            val: result7
          };
          break;
        }
        case 3: {
          var ptr8 = dataView(memory0).getUint32(ret + 12, true);
          var len8 = dataView(memory0).getUint32(ret + 16, true);
          var result8 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr8, len8));
          variant10= {
            tag: 'syntax',
            val: result8
          };
          break;
        }
        case 4: {
          var ptr9 = dataView(memory0).getUint32(ret + 12, true);
          var len9 = dataView(memory0).getUint32(ret + 16, true);
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
  
}
let numericsSqrtInteger;

function sqrtInteger(arg0) {
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
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'numericsSqrtInteger',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => numericsSqrtInteger(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1),
  });
  
  let variant9;
  switch (dataView(memory0).getUint8(ret + 0, true)) {
    case 0: {
      let enum2;
      switch (dataView(memory0).getUint8(ret + 40, true)) {
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
          r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 8, true))),
          r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 16, true))),
          r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 24, true))),
          r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 32, true))),
          sign: enum2,
        }
      };
      break;
    }
    case 1: {
      let variant8;
      switch (dataView(memory0).getUint8(ret + 8, true)) {
        case 0: {
          var ptr3 = dataView(memory0).getUint32(ret + 12, true);
          var len3 = dataView(memory0).getUint32(ret + 16, true);
          var result3 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr3, len3));
          variant8= {
            tag: 'message',
            val: result3
          };
          break;
        }
        case 1: {
          var ptr4 = dataView(memory0).getUint32(ret + 12, true);
          var len4 = dataView(memory0).getUint32(ret + 16, true);
          var result4 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr4, len4));
          variant8= {
            tag: 'overflow',
            val: result4
          };
          break;
        }
        case 2: {
          var ptr5 = dataView(memory0).getUint32(ret + 12, true);
          var len5 = dataView(memory0).getUint32(ret + 16, true);
          var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
          variant8= {
            tag: 'div-by-zero',
            val: result5
          };
          break;
        }
        case 3: {
          var ptr6 = dataView(memory0).getUint32(ret + 12, true);
          var len6 = dataView(memory0).getUint32(ret + 16, true);
          var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
          variant8= {
            tag: 'syntax',
            val: result6
          };
          break;
        }
        case 4: {
          var ptr7 = dataView(memory0).getUint32(ret + 12, true);
          var len7 = dataView(memory0).getUint32(ret + 16, true);
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
  
}
let numericsIntegerToDecimal;

function integerToDecimal(arg0) {
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
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'numericsIntegerToDecimal',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => numericsIntegerToDecimal(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1),
  });
  
  let variant9;
  switch (dataView(memory0).getUint8(ret + 0, true)) {
    case 0: {
      let enum2;
      switch (dataView(memory0).getUint8(ret + 40, true)) {
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
          r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 8, true))),
          r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 16, true))),
          r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 24, true))),
          r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 32, true))),
          sign: enum2,
        }
      };
      break;
    }
    case 1: {
      let variant8;
      switch (dataView(memory0).getUint8(ret + 8, true)) {
        case 0: {
          var ptr3 = dataView(memory0).getUint32(ret + 12, true);
          var len3 = dataView(memory0).getUint32(ret + 16, true);
          var result3 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr3, len3));
          variant8= {
            tag: 'message',
            val: result3
          };
          break;
        }
        case 1: {
          var ptr4 = dataView(memory0).getUint32(ret + 12, true);
          var len4 = dataView(memory0).getUint32(ret + 16, true);
          var result4 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr4, len4));
          variant8= {
            tag: 'overflow',
            val: result4
          };
          break;
        }
        case 2: {
          var ptr5 = dataView(memory0).getUint32(ret + 12, true);
          var len5 = dataView(memory0).getUint32(ret + 16, true);
          var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
          variant8= {
            tag: 'div-by-zero',
            val: result5
          };
          break;
        }
        case 3: {
          var ptr6 = dataView(memory0).getUint32(ret + 12, true);
          var len6 = dataView(memory0).getUint32(ret + 16, true);
          var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
          variant8= {
            tag: 'syntax',
            val: result6
          };
          break;
        }
        case 4: {
          var ptr7 = dataView(memory0).getUint32(ret + 12, true);
          var len7 = dataView(memory0).getUint32(ret + 16, true);
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
  
}
let numericsDecimalToInteger;

function decimalToInteger(arg0) {
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
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'numericsDecimalToInteger',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => numericsDecimalToInteger(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1),
  });
  
  let variant9;
  switch (dataView(memory0).getUint8(ret + 0, true)) {
    case 0: {
      let enum2;
      switch (dataView(memory0).getUint8(ret + 40, true)) {
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
          r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 8, true))),
          r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 16, true))),
          r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 24, true))),
          r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 32, true))),
          sign: enum2,
        }
      };
      break;
    }
    case 1: {
      let variant8;
      switch (dataView(memory0).getUint8(ret + 8, true)) {
        case 0: {
          var ptr3 = dataView(memory0).getUint32(ret + 12, true);
          var len3 = dataView(memory0).getUint32(ret + 16, true);
          var result3 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr3, len3));
          variant8= {
            tag: 'message',
            val: result3
          };
          break;
        }
        case 1: {
          var ptr4 = dataView(memory0).getUint32(ret + 12, true);
          var len4 = dataView(memory0).getUint32(ret + 16, true);
          var result4 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr4, len4));
          variant8= {
            tag: 'overflow',
            val: result4
          };
          break;
        }
        case 2: {
          var ptr5 = dataView(memory0).getUint32(ret + 12, true);
          var len5 = dataView(memory0).getUint32(ret + 16, true);
          var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
          variant8= {
            tag: 'div-by-zero',
            val: result5
          };
          break;
        }
        case 3: {
          var ptr6 = dataView(memory0).getUint32(ret + 12, true);
          var len6 = dataView(memory0).getUint32(ret + 16, true);
          var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
          variant8= {
            tag: 'syntax',
            val: result6
          };
          break;
        }
        case 4: {
          var ptr7 = dataView(memory0).getUint32(ret + 12, true);
          var len7 = dataView(memory0).getUint32(ret + 16, true);
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
  
}
let numericsU64ToDecimal;

function u64ToDecimal(arg0) {
  _debugLog('[iface="root:component/numerics", function="u64-to-decimal"][Instruction::CallWasm] enter', {
    funcName: 'u64-to-decimal',
    paramCount: 1,
    async: false,
    postReturn: true,
  });
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'numericsU64ToDecimal',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => numericsU64ToDecimal(toUint64(arg0)),
  });
  
  let variant7;
  switch (dataView(memory0).getUint8(ret + 0, true)) {
    case 0: {
      let enum0;
      switch (dataView(memory0).getUint8(ret + 40, true)) {
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
          r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 8, true))),
          r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 16, true))),
          r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 24, true))),
          r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 32, true))),
          sign: enum0,
        }
      };
      break;
    }
    case 1: {
      let variant6;
      switch (dataView(memory0).getUint8(ret + 8, true)) {
        case 0: {
          var ptr1 = dataView(memory0).getUint32(ret + 12, true);
          var len1 = dataView(memory0).getUint32(ret + 16, true);
          var result1 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr1, len1));
          variant6= {
            tag: 'message',
            val: result1
          };
          break;
        }
        case 1: {
          var ptr2 = dataView(memory0).getUint32(ret + 12, true);
          var len2 = dataView(memory0).getUint32(ret + 16, true);
          var result2 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr2, len2));
          variant6= {
            tag: 'overflow',
            val: result2
          };
          break;
        }
        case 2: {
          var ptr3 = dataView(memory0).getUint32(ret + 12, true);
          var len3 = dataView(memory0).getUint32(ret + 16, true);
          var result3 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr3, len3));
          variant6= {
            tag: 'div-by-zero',
            val: result3
          };
          break;
        }
        case 3: {
          var ptr4 = dataView(memory0).getUint32(ret + 12, true);
          var len4 = dataView(memory0).getUint32(ret + 16, true);
          var result4 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr4, len4));
          variant6= {
            tag: 'syntax',
            val: result4
          };
          break;
        }
        case 4: {
          var ptr5 = dataView(memory0).getUint32(ret + 12, true);
          var len5 = dataView(memory0).getUint32(ret + 16, true);
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
  
}
let numericsS64ToDecimal;

function s64ToDecimal(arg0) {
  _debugLog('[iface="root:component/numerics", function="s64-to-decimal"][Instruction::CallWasm] enter', {
    funcName: 's64-to-decimal',
    paramCount: 1,
    async: false,
    postReturn: true,
  });
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'numericsS64ToDecimal',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => numericsS64ToDecimal(toInt64(arg0)),
  });
  
  let variant7;
  switch (dataView(memory0).getUint8(ret + 0, true)) {
    case 0: {
      let enum0;
      switch (dataView(memory0).getUint8(ret + 40, true)) {
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
          r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 8, true))),
          r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 16, true))),
          r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 24, true))),
          r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 32, true))),
          sign: enum0,
        }
      };
      break;
    }
    case 1: {
      let variant6;
      switch (dataView(memory0).getUint8(ret + 8, true)) {
        case 0: {
          var ptr1 = dataView(memory0).getUint32(ret + 12, true);
          var len1 = dataView(memory0).getUint32(ret + 16, true);
          var result1 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr1, len1));
          variant6= {
            tag: 'message',
            val: result1
          };
          break;
        }
        case 1: {
          var ptr2 = dataView(memory0).getUint32(ret + 12, true);
          var len2 = dataView(memory0).getUint32(ret + 16, true);
          var result2 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr2, len2));
          variant6= {
            tag: 'overflow',
            val: result2
          };
          break;
        }
        case 2: {
          var ptr3 = dataView(memory0).getUint32(ret + 12, true);
          var len3 = dataView(memory0).getUint32(ret + 16, true);
          var result3 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr3, len3));
          variant6= {
            tag: 'div-by-zero',
            val: result3
          };
          break;
        }
        case 3: {
          var ptr4 = dataView(memory0).getUint32(ret + 12, true);
          var len4 = dataView(memory0).getUint32(ret + 16, true);
          var result4 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr4, len4));
          variant6= {
            tag: 'syntax',
            val: result4
          };
          break;
        }
        case 4: {
          var ptr5 = dataView(memory0).getUint32(ret + 12, true);
          var len5 = dataView(memory0).getUint32(ret + 16, true);
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
  
}
let numericsF64ToDecimal;

function f64ToDecimal(arg0) {
  _debugLog('[iface="root:component/numerics", function="f64-to-decimal"][Instruction::CallWasm] enter', {
    funcName: 'f64-to-decimal',
    paramCount: 1,
    async: false,
    postReturn: true,
  });
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'numericsF64ToDecimal',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => numericsF64ToDecimal(+arg0),
  });
  
  let variant7;
  switch (dataView(memory0).getUint8(ret + 0, true)) {
    case 0: {
      let enum0;
      switch (dataView(memory0).getUint8(ret + 40, true)) {
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
          r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 8, true))),
          r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 16, true))),
          r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 24, true))),
          r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 32, true))),
          sign: enum0,
        }
      };
      break;
    }
    case 1: {
      let variant6;
      switch (dataView(memory0).getUint8(ret + 8, true)) {
        case 0: {
          var ptr1 = dataView(memory0).getUint32(ret + 12, true);
          var len1 = dataView(memory0).getUint32(ret + 16, true);
          var result1 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr1, len1));
          variant6= {
            tag: 'message',
            val: result1
          };
          break;
        }
        case 1: {
          var ptr2 = dataView(memory0).getUint32(ret + 12, true);
          var len2 = dataView(memory0).getUint32(ret + 16, true);
          var result2 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr2, len2));
          variant6= {
            tag: 'overflow',
            val: result2
          };
          break;
        }
        case 2: {
          var ptr3 = dataView(memory0).getUint32(ret + 12, true);
          var len3 = dataView(memory0).getUint32(ret + 16, true);
          var result3 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr3, len3));
          variant6= {
            tag: 'div-by-zero',
            val: result3
          };
          break;
        }
        case 3: {
          var ptr4 = dataView(memory0).getUint32(ret + 12, true);
          var len4 = dataView(memory0).getUint32(ret + 16, true);
          var result4 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr4, len4));
          variant6= {
            tag: 'syntax',
            val: result4
          };
          break;
        }
        case 4: {
          var ptr5 = dataView(memory0).getUint32(ret + 12, true);
          var len5 = dataView(memory0).getUint32(ret + 16, true);
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
  
}
let numericsStringToDecimal;

function stringToDecimal(arg0) {
  
  var encodeRes = _utf8AllocateAndEncode(arg0, realloc0, memory0);
  var ptr0= encodeRes.ptr;
  var len0 = encodeRes.len;
  
  _debugLog('[iface="root:component/numerics", function="string-to-decimal"][Instruction::CallWasm] enter', {
    funcName: 'string-to-decimal',
    paramCount: 2,
    async: false,
    postReturn: true,
  });
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'numericsStringToDecimal',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => numericsStringToDecimal(ptr0, len0),
  });
  
  let variant8;
  switch (dataView(memory0).getUint8(ret + 0, true)) {
    case 0: {
      let enum1;
      switch (dataView(memory0).getUint8(ret + 40, true)) {
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
          r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 8, true))),
          r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 16, true))),
          r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 24, true))),
          r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 32, true))),
          sign: enum1,
        }
      };
      break;
    }
    case 1: {
      let variant7;
      switch (dataView(memory0).getUint8(ret + 8, true)) {
        case 0: {
          var ptr2 = dataView(memory0).getUint32(ret + 12, true);
          var len2 = dataView(memory0).getUint32(ret + 16, true);
          var result2 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr2, len2));
          variant7= {
            tag: 'message',
            val: result2
          };
          break;
        }
        case 1: {
          var ptr3 = dataView(memory0).getUint32(ret + 12, true);
          var len3 = dataView(memory0).getUint32(ret + 16, true);
          var result3 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr3, len3));
          variant7= {
            tag: 'overflow',
            val: result3
          };
          break;
        }
        case 2: {
          var ptr4 = dataView(memory0).getUint32(ret + 12, true);
          var len4 = dataView(memory0).getUint32(ret + 16, true);
          var result4 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr4, len4));
          variant7= {
            tag: 'div-by-zero',
            val: result4
          };
          break;
        }
        case 3: {
          var ptr5 = dataView(memory0).getUint32(ret + 12, true);
          var len5 = dataView(memory0).getUint32(ret + 16, true);
          var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
          variant7= {
            tag: 'syntax',
            val: result5
          };
          break;
        }
        case 4: {
          var ptr6 = dataView(memory0).getUint32(ret + 12, true);
          var len6 = dataView(memory0).getUint32(ret + 16, true);
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
  
}
let numericsDecimalToString;

function decimalToString(arg0) {
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
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'numericsDecimalToString',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'none',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => numericsDecimalToString(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1),
  });
  
  var ptr2 = dataView(memory0).getUint32(ret + 0, true);
  var len2 = dataView(memory0).getUint32(ret + 4, true);
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
  postReturn0(ret);
  cstate.mayLeave = true;
  task.exit();
  return retCopy;
  
}
let numericsEqDecimal;

function eqDecimal(arg0, arg1) {
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
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'numericsEqDecimal',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => numericsEqDecimal(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1, toUint64(v2_0), toUint64(v2_1), toUint64(v2_2), toUint64(v2_3), enum3),
  });
  
  let variant11;
  switch (dataView(memory0).getUint8(ret + 0, true)) {
    case 0: {
      var bool4 = dataView(memory0).getUint8(ret + 4, true);
      variant11= {
        tag: 'ok',
        val: bool4 == 0 ? false : (bool4 == 1 ? true : throwInvalidBool())
      };
      break;
    }
    case 1: {
      let variant10;
      switch (dataView(memory0).getUint8(ret + 4, true)) {
        case 0: {
          var ptr5 = dataView(memory0).getUint32(ret + 8, true);
          var len5 = dataView(memory0).getUint32(ret + 12, true);
          var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
          variant10= {
            tag: 'message',
            val: result5
          };
          break;
        }
        case 1: {
          var ptr6 = dataView(memory0).getUint32(ret + 8, true);
          var len6 = dataView(memory0).getUint32(ret + 12, true);
          var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
          variant10= {
            tag: 'overflow',
            val: result6
          };
          break;
        }
        case 2: {
          var ptr7 = dataView(memory0).getUint32(ret + 8, true);
          var len7 = dataView(memory0).getUint32(ret + 12, true);
          var result7 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr7, len7));
          variant10= {
            tag: 'div-by-zero',
            val: result7
          };
          break;
        }
        case 3: {
          var ptr8 = dataView(memory0).getUint32(ret + 8, true);
          var len8 = dataView(memory0).getUint32(ret + 12, true);
          var result8 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr8, len8));
          variant10= {
            tag: 'syntax',
            val: result8
          };
          break;
        }
        case 4: {
          var ptr9 = dataView(memory0).getUint32(ret + 8, true);
          var len9 = dataView(memory0).getUint32(ret + 12, true);
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
  postReturn4(ret);
  cstate.mayLeave = true;
  task.exit();
  
  
  
  if (typeof retCopy === 'object' && retCopy.tag === 'err') {
    throw new ComponentError(retCopy.val);
  }
  return retCopy.val;
  
}
let numericsCmpDecimal;

function cmpDecimal(arg0, arg1) {
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
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'numericsCmpDecimal',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'none',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => numericsCmpDecimal(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1, toUint64(v2_0), toUint64(v2_1), toUint64(v2_2), toUint64(v2_3), enum3),
  });
  
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
}
let numericsAddDecimal;

function addDecimal(arg0, arg1) {
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
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'numericsAddDecimal',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => numericsAddDecimal(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1, toUint64(v2_0), toUint64(v2_1), toUint64(v2_2), toUint64(v2_3), enum3),
  });
  
  let variant11;
  switch (dataView(memory0).getUint8(ret + 0, true)) {
    case 0: {
      let enum4;
      switch (dataView(memory0).getUint8(ret + 40, true)) {
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
          r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 8, true))),
          r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 16, true))),
          r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 24, true))),
          r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 32, true))),
          sign: enum4,
        }
      };
      break;
    }
    case 1: {
      let variant10;
      switch (dataView(memory0).getUint8(ret + 8, true)) {
        case 0: {
          var ptr5 = dataView(memory0).getUint32(ret + 12, true);
          var len5 = dataView(memory0).getUint32(ret + 16, true);
          var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
          variant10= {
            tag: 'message',
            val: result5
          };
          break;
        }
        case 1: {
          var ptr6 = dataView(memory0).getUint32(ret + 12, true);
          var len6 = dataView(memory0).getUint32(ret + 16, true);
          var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
          variant10= {
            tag: 'overflow',
            val: result6
          };
          break;
        }
        case 2: {
          var ptr7 = dataView(memory0).getUint32(ret + 12, true);
          var len7 = dataView(memory0).getUint32(ret + 16, true);
          var result7 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr7, len7));
          variant10= {
            tag: 'div-by-zero',
            val: result7
          };
          break;
        }
        case 3: {
          var ptr8 = dataView(memory0).getUint32(ret + 12, true);
          var len8 = dataView(memory0).getUint32(ret + 16, true);
          var result8 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr8, len8));
          variant10= {
            tag: 'syntax',
            val: result8
          };
          break;
        }
        case 4: {
          var ptr9 = dataView(memory0).getUint32(ret + 12, true);
          var len9 = dataView(memory0).getUint32(ret + 16, true);
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
  
}
let numericsSubDecimal;

function subDecimal(arg0, arg1) {
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
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'numericsSubDecimal',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => numericsSubDecimal(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1, toUint64(v2_0), toUint64(v2_1), toUint64(v2_2), toUint64(v2_3), enum3),
  });
  
  let variant11;
  switch (dataView(memory0).getUint8(ret + 0, true)) {
    case 0: {
      let enum4;
      switch (dataView(memory0).getUint8(ret + 40, true)) {
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
          r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 8, true))),
          r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 16, true))),
          r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 24, true))),
          r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 32, true))),
          sign: enum4,
        }
      };
      break;
    }
    case 1: {
      let variant10;
      switch (dataView(memory0).getUint8(ret + 8, true)) {
        case 0: {
          var ptr5 = dataView(memory0).getUint32(ret + 12, true);
          var len5 = dataView(memory0).getUint32(ret + 16, true);
          var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
          variant10= {
            tag: 'message',
            val: result5
          };
          break;
        }
        case 1: {
          var ptr6 = dataView(memory0).getUint32(ret + 12, true);
          var len6 = dataView(memory0).getUint32(ret + 16, true);
          var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
          variant10= {
            tag: 'overflow',
            val: result6
          };
          break;
        }
        case 2: {
          var ptr7 = dataView(memory0).getUint32(ret + 12, true);
          var len7 = dataView(memory0).getUint32(ret + 16, true);
          var result7 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr7, len7));
          variant10= {
            tag: 'div-by-zero',
            val: result7
          };
          break;
        }
        case 3: {
          var ptr8 = dataView(memory0).getUint32(ret + 12, true);
          var len8 = dataView(memory0).getUint32(ret + 16, true);
          var result8 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr8, len8));
          variant10= {
            tag: 'syntax',
            val: result8
          };
          break;
        }
        case 4: {
          var ptr9 = dataView(memory0).getUint32(ret + 12, true);
          var len9 = dataView(memory0).getUint32(ret + 16, true);
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
  
}
let numericsMulDecimal;

function mulDecimal(arg0, arg1) {
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
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'numericsMulDecimal',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => numericsMulDecimal(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1, toUint64(v2_0), toUint64(v2_1), toUint64(v2_2), toUint64(v2_3), enum3),
  });
  
  let variant11;
  switch (dataView(memory0).getUint8(ret + 0, true)) {
    case 0: {
      let enum4;
      switch (dataView(memory0).getUint8(ret + 40, true)) {
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
          r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 8, true))),
          r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 16, true))),
          r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 24, true))),
          r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 32, true))),
          sign: enum4,
        }
      };
      break;
    }
    case 1: {
      let variant10;
      switch (dataView(memory0).getUint8(ret + 8, true)) {
        case 0: {
          var ptr5 = dataView(memory0).getUint32(ret + 12, true);
          var len5 = dataView(memory0).getUint32(ret + 16, true);
          var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
          variant10= {
            tag: 'message',
            val: result5
          };
          break;
        }
        case 1: {
          var ptr6 = dataView(memory0).getUint32(ret + 12, true);
          var len6 = dataView(memory0).getUint32(ret + 16, true);
          var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
          variant10= {
            tag: 'overflow',
            val: result6
          };
          break;
        }
        case 2: {
          var ptr7 = dataView(memory0).getUint32(ret + 12, true);
          var len7 = dataView(memory0).getUint32(ret + 16, true);
          var result7 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr7, len7));
          variant10= {
            tag: 'div-by-zero',
            val: result7
          };
          break;
        }
        case 3: {
          var ptr8 = dataView(memory0).getUint32(ret + 12, true);
          var len8 = dataView(memory0).getUint32(ret + 16, true);
          var result8 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr8, len8));
          variant10= {
            tag: 'syntax',
            val: result8
          };
          break;
        }
        case 4: {
          var ptr9 = dataView(memory0).getUint32(ret + 12, true);
          var len9 = dataView(memory0).getUint32(ret + 16, true);
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
  
}
let numericsDivDecimal;

function divDecimal(arg0, arg1) {
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
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'numericsDivDecimal',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => numericsDivDecimal(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1, toUint64(v2_0), toUint64(v2_1), toUint64(v2_2), toUint64(v2_3), enum3),
  });
  
  let variant11;
  switch (dataView(memory0).getUint8(ret + 0, true)) {
    case 0: {
      let enum4;
      switch (dataView(memory0).getUint8(ret + 40, true)) {
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
          r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 8, true))),
          r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 16, true))),
          r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 24, true))),
          r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 32, true))),
          sign: enum4,
        }
      };
      break;
    }
    case 1: {
      let variant10;
      switch (dataView(memory0).getUint8(ret + 8, true)) {
        case 0: {
          var ptr5 = dataView(memory0).getUint32(ret + 12, true);
          var len5 = dataView(memory0).getUint32(ret + 16, true);
          var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
          variant10= {
            tag: 'message',
            val: result5
          };
          break;
        }
        case 1: {
          var ptr6 = dataView(memory0).getUint32(ret + 12, true);
          var len6 = dataView(memory0).getUint32(ret + 16, true);
          var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
          variant10= {
            tag: 'overflow',
            val: result6
          };
          break;
        }
        case 2: {
          var ptr7 = dataView(memory0).getUint32(ret + 12, true);
          var len7 = dataView(memory0).getUint32(ret + 16, true);
          var result7 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr7, len7));
          variant10= {
            tag: 'div-by-zero',
            val: result7
          };
          break;
        }
        case 3: {
          var ptr8 = dataView(memory0).getUint32(ret + 12, true);
          var len8 = dataView(memory0).getUint32(ret + 16, true);
          var result8 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr8, len8));
          variant10= {
            tag: 'syntax',
            val: result8
          };
          break;
        }
        case 4: {
          var ptr9 = dataView(memory0).getUint32(ret + 12, true);
          var len9 = dataView(memory0).getUint32(ret + 16, true);
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
  
}
let numericsLog10Decimal;

function log10Decimal(arg0) {
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
  const hostProvided = false;
  
  const [task, _wasm_call_currentTaskID] = createNewCurrentTask({
    componentIdx: 0,
    isAsync: false,
    isManualAsync: false,
    entryFnName: 'numericsLog10Decimal',
    getCallbackFn: () => null,
    callbackFnName: 'null',
    errHandling: 'throw-result-err',
    callingWasmExport: true,
  });
  
  const started = task.enterSync();
  task.setReturnMemoryIdx(0);
  task.setReturnMemory(memory0);
  let ret =   _withGlobalCurrentTaskMeta({
    taskID: task.id(),
    componentIdx: task.componentIdx(),
    fn: () => numericsLog10Decimal(toUint64(v0_0), toUint64(v0_1), toUint64(v0_2), toUint64(v0_3), enum1),
  });
  
  let variant9;
  switch (dataView(memory0).getUint8(ret + 0, true)) {
    case 0: {
      let enum2;
      switch (dataView(memory0).getUint8(ret + 40, true)) {
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
          r0: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 8, true))),
          r1: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 16, true))),
          r2: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 24, true))),
          r3: BigInt.asUintN(64, BigInt(dataView(memory0).getBigInt64(ret + 32, true))),
          sign: enum2,
        }
      };
      break;
    }
    case 1: {
      let variant8;
      switch (dataView(memory0).getUint8(ret + 8, true)) {
        case 0: {
          var ptr3 = dataView(memory0).getUint32(ret + 12, true);
          var len3 = dataView(memory0).getUint32(ret + 16, true);
          var result3 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr3, len3));
          variant8= {
            tag: 'message',
            val: result3
          };
          break;
        }
        case 1: {
          var ptr4 = dataView(memory0).getUint32(ret + 12, true);
          var len4 = dataView(memory0).getUint32(ret + 16, true);
          var result4 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr4, len4));
          variant8= {
            tag: 'overflow',
            val: result4
          };
          break;
        }
        case 2: {
          var ptr5 = dataView(memory0).getUint32(ret + 12, true);
          var len5 = dataView(memory0).getUint32(ret + 16, true);
          var result5 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr5, len5));
          variant8= {
            tag: 'div-by-zero',
            val: result5
          };
          break;
        }
        case 3: {
          var ptr6 = dataView(memory0).getUint32(ret + 12, true);
          var len6 = dataView(memory0).getUint32(ret + 16, true);
          var result6 = TEXT_DECODER_UTF8.decode(new Uint8Array(memory0.buffer, ptr6, len6));
          variant8= {
            tag: 'syntax',
            val: result6
          };
          break;
        }
        case 4: {
          var ptr7 = dataView(memory0).getUint32(ret + 12, true);
          var len7 = dataView(memory0).getUint32(ret + 16, true);
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
  
}
const trampoline0 = rscTableCreateOwn.bind(null, handleTable0);

const $init = (() => {
  let gen = (function* _initGenerator () {
    const module0 = fetchCompile(new URL('./kontor-sdk.core.wasm', import.meta.url));
    const module1 = base64Compile('AGFzbQEAAAABBQFgAX8AAwIBAAQFAXABAQEHEAIBMAAACCRpbXBvcnRzAQAKCwEJACAAQQARAAALAC8JcHJvZHVjZXJzAQxwcm9jZXNzZWQtYnkBDXdpdC1jb21wb25lbnQHMC4yNDQuMA');
    const module2 = base64Compile('AGFzbQEAAAABBQFgAX8AAhUCAAEwAAAACCRpbXBvcnRzAXABAQEJBwEAQQALAQAALwlwcm9kdWNlcnMBDHByb2Nlc3NlZC1ieQENd2l0LWNvbXBvbmVudAcwLjI0NC4w');
    ({ exports: exports0 } = yield instantiateCore(yield module1));
    ({ exports: exports1 } = yield instantiateCore(yield module0, {
      '[export]root:component/wit-codec': {
        '[resource-new]wit': trampoline0,
      },
    }));
    ({ exports: exports2 } = yield instantiateCore(yield module2, {
      '': {
        $imports: exports0.$imports,
        '0': exports1['root:component/wit-codec#[dtor]wit'],
      },
    }));
    memory0 = exports1.memory;
    realloc0 = exports1.cabi_realloc;
    
    try {
      realloc0Async = WebAssembly.promising(exports1.cabi_realloc);
    } catch(err) {
      realloc0Async = exports1.cabi_realloc;
    }
    
    postReturn0 = exports1['cabi_post_deserialize-inst'];
    
    try {
      postReturn0Async = WebAssembly.promising(exports1['cabi_post_deserialize-inst']);
    } catch(err) {
      postReturn0Async = exports1['cabi_post_deserialize-inst'];
    }
    
    postReturn1 = exports1['cabi_post_validate-wit'];
    
    try {
      postReturn1Async = WebAssembly.promising(exports1['cabi_post_validate-wit']);
    } catch(err) {
      postReturn1Async = exports1['cabi_post_validate-wit'];
    }
    
    postReturn2 = exports1['cabi_post_root:component/wit-codec#[method]wit.decode-result'];
    
    try {
      postReturn2Async = WebAssembly.promising(exports1['cabi_post_root:component/wit-codec#[method]wit.decode-result']);
    } catch(err) {
      postReturn2Async = exports1['cabi_post_root:component/wit-codec#[method]wit.decode-result'];
    }
    
    postReturn3 = exports1['cabi_post_root:component/numerics#add-decimal'];
    
    try {
      postReturn3Async = WebAssembly.promising(exports1['cabi_post_root:component/numerics#add-decimal']);
    } catch(err) {
      postReturn3Async = exports1['cabi_post_root:component/numerics#add-decimal'];
    }
    
    postReturn4 = exports1['cabi_post_root:component/numerics#eq-decimal'];
    
    try {
      postReturn4Async = WebAssembly.promising(exports1['cabi_post_root:component/numerics#eq-decimal']);
    } catch(err) {
      postReturn4Async = exports1['cabi_post_root:component/numerics#eq-decimal'];
    }
    
    exports1SerializeInst = exports1['serialize-inst'];
    exports1DeserializeInst = exports1['deserialize-inst'];
    exports1SerializeOpReturnData = exports1['serialize-op-return-data'];
    exports1DeserializeOpReturnData = exports1['deserialize-op-return-data'];
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
  function runNext (value) {
    try {
      let done;
      do {
        ({ value, done } = gen.next(value));
      } while (!(value instanceof Promise) && !done);
      if (done) {
        if (resolve) resolve(value);
        else return value;
      }
      if (!promise) promise = new Promise((_resolve, _reject) => (resolve = _resolve, reject = _reject));
      value.then(runNext, reject);
    }
    catch (e) {
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

export { numerics, witCodec, deserializeInst, deserializeOpReturnData, numerics as 'root:component/numerics', witCodec as 'root:component/wit-codec', serializeInst, serializeOpReturnData, validateWit,  }