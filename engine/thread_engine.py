from threading import Thread
from engine.core import critical, info


class ThreadEngine(object):
    def __init__(self, max_threads):
        if max_threads < 1:
            print(critical('Threads number must be > 0'))
            exit()
        self.max_threads = max_threads
        self.threads = []
        print(info('Start %d threads ...' % self.max_threads))

    def new_task(self, task, args):
        """ Launch the new task in a thread """
        self.launch_task(task, args)

    def launch_task(self, task, args):
        """ Launch task in a new thread """
        t = Thread(target=task, args=args)
        self.threads.append(t)
        t.start()

    def wait(self):
        """ Wait for threads to complete """
        for thread in self.threads:
            thread.join()
