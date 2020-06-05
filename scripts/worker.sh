#!/bin/sh
PATH=$PATH:/tmp/rust/.cargo/bin
celery worker --app=src.tasks.tasks