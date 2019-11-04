from celery import Celery


app = Celery()
# noinspection PyUnusedName
app.conf.task_serializer = "pickle"
# noinspection PyUnusedName
app.conf.result_serializer = "pickle"
# noinspection PyUnusedName
app.conf.accept_content = {"pickle"}