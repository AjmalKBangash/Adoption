from celery import shared_task
from time import sleep

@shared_task
def add(x, y):
    print('Before Sleep /////////////////////////////')
    sleep(10)
    print('After Sleep /////////////////////////////')
    return x + y

# @shared_task
# def Notify(x, y):
#     print('Before Sleep No /////////////////////////////')
#     sleep(5)
#     print('After Sleep No /////////////////////////////')
#     return x + y
