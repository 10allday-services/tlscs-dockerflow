from src.db import models
import src.tasks.tasks as tasks
from flask import Blueprint, request
import logging
from typing import Tuple, Dict

log = logging.getLogger("web.api")

views_blueprint = app = Blueprint("views_blueprint", __name__)


@app.route("/", methods=["GET"])
def hello() -> Tuple[str, int]:
    log.info("someone said hello")
    return "Hello World!", 200

@app.route("/job/<job_type>", methods=["GET"])
def job(job_type) -> Tuple[str, int]:
    task_id = tasks.job_task.delay(job_type)
    log.info("started a job task")
    return f"job task started with id {task_id}", 200


@app.route("/<input_name>", methods=["GET"])
def hello_name(input_name) -> Tuple[str, int]:
    log.info(f"{input_name} said hello", extra={"input_name": input_name})
    return f"Hello {input_name}", 200


@app.route("/user/<input_name>", methods=["GET"])
def get_user(input_name) -> Tuple[Dict, int]:
    log.info(f"retrieving user details", extra={"input_name": input_name})
    return models.get_user_details(input_name), 200


@app.route("/user", methods=["POST"])
def create_user() -> Tuple[Dict, int]:
    user_details = request.json
    log.info(
        f"creating user", extra={"details": user_details},
    )
    return models.post_user_details(user_details), 202
