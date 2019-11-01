from threading import RLock


class AsyncResultQueue(object):

    """
        A FIFO queue , meant to hold celery.Result
        returns the results in the order they are ready()
    """

    def __init__(self):
        self.qlock = RLock()
        self.queue = []


    def empty(self):
        with self.qlock:
            return len(self.queue) == 0

    """ emplace an element at the end of the queue """

    def put(self, asyncresult):
        with self.qlock:
            self.queue.append(asyncresult)

    """ get the first .ready() item in the queue, return None if none are .ready() yet """

    def get(self):
        with self.qlock:
            for index, element in enumerate(self.queue):
                if element.ready():
                    del self.queue[index]
                    return element
