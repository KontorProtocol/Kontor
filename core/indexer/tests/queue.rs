use indexer::runtime::queue::Queue;
use tokio::task;

#[tokio::test]
async fn test_push_and_take_all_single_task() {
    let queue = Queue::new();

    queue.push(1).await;
    queue.push(2).await;
    queue.push(3).await;

    let result = queue.take_all().await;
    assert_eq!(result, vec![1, 2, 3]);

    let result = queue.take_all().await;
    assert!(result.is_empty());
}

#[tokio::test]
async fn test_push_empty_take_all() {
    let queue = Queue::<i32>::new();

    let result = queue.take_all().await;
    assert!(result.is_empty());
}

#[tokio::test]
async fn test_concurrent_push_and_take_all() {
    let queue = Queue::new();
    let queue_clone1 = queue.clone();
    let queue_clone2 = queue.clone();

    let producer1 = task::spawn(async move {
        for i in 0..5 {
            queue_clone1.push(i).await;
        }
    });

    let producer2 = task::spawn(async move {
        for i in 5..10 {
            queue_clone2.push(i).await;
        }
    });

    producer1.await.unwrap();
    producer2.await.unwrap();

    let result = queue.take_all().await;

    assert_eq!(result.len(), 10);
    for i in 0..10 {
        assert!(result.contains(&i));
    }

    let result = queue.take_all().await;
    assert!(result.is_empty());
}

#[tokio::test]
async fn test_clone_and_independent_pushes() {
    let queue1 = Queue::new();
    let queue2 = queue1.clone();

    queue1.push("hello").await;
    queue2.push("world").await;

    let result = queue1.take_all().await;
    assert_eq!(result.len(), 2);
    assert!(result.contains(&"hello"));
    assert!(result.contains(&"world"));

    let result = queue2.take_all().await;
    assert!(result.is_empty());
}

#[tokio::test]
async fn test_replace_last_empty_queue() {
    let queue = Queue::new();

    queue.replace_last(42).await;

    let result = queue.take_all().await;
    assert_eq!(result, vec![42]);
}

#[tokio::test]
async fn test_replace_last_single_element() {
    let queue = Queue::new();

    queue.push(1).await;
    queue.replace_last(42).await;

    let result = queue.take_all().await;
    assert_eq!(result, vec![42]);
}

#[tokio::test]
async fn test_replace_last_multiple_elements() {
    let queue = Queue::new();

    queue.push(1).await;
    queue.push(2).await;
    queue.push(3).await;

    queue.replace_last(42).await;

    let result = queue.take_all().await;
    assert_eq!(result, vec![1, 2, 42]);
}

#[tokio::test]
async fn test_concurrent_replace_last() {
    let queue = Queue::new();
    let queue_clone1 = queue.clone();
    let queue_clone2 = queue.clone();

    queue.push(1).await;
    queue.push(2).await;
    queue.push(3).await;

    let replacer1 = task::spawn(async move {
        queue_clone1.replace_last(100).await;
    });

    let replacer2 = task::spawn(async move {
        queue_clone2.replace_last(200).await;
    });

    replacer1.await.unwrap();
    replacer2.await.unwrap();

    let result = queue.take_all().await;
    assert_eq!(result.len(), 3);
    assert_eq!(result[2], 200);
    assert_eq!(result[0], 1);
    assert_eq!(result[1], 2);
}

#[tokio::test]
async fn test_mixed_push_and_replace_last() {
    let queue = Queue::new();

    queue.push(1).await;
    queue.replace_last(10).await; // [10]
    queue.push(2).await; // [10, 2]
    queue.replace_last(20).await; // [10, 20]
    queue.push(3).await; // [10, 20, 3]
    queue.replace_last(30).await; // [10, 20, 30]

    let result = queue.take_all().await;
    assert_eq!(result, vec![10, 20, 30]);
}
