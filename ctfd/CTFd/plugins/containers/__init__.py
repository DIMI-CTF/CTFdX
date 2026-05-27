from __future__ import division

import time
import json
import datetime
import math

from flask import Blueprint, request, Flask, render_template, url_for, redirect, flash

from CTFd.models import db, Solves
from CTFd.plugins import register_plugin_assets_directory
from CTFd.plugins.challenges import CHALLENGE_CLASSES, BaseChallenge
from CTFd.utils.decorators import authed_only, admins_only, during_ctf_time_only, ratelimit, require_verified_emails
from CTFd.utils.user import get_current_user
from CTFd.utils.modes import get_model
from CTFd.utils import get_config

from .models import ContainerChallengeModel, ContainerInfoModel, ContainerSettingsModel
from .container_manager import ContainerManager, ContainerException

def get_settings_path():
    import os
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "settings.json")

settings = json.load(open(get_settings_path()))

USERS_MODE = settings["modes"]["USERS_MODE"]
TEAMS_MODE = settings["modes"]["TEAMS_MODE"]


class ContainerChallenge(BaseChallenge):
    id = settings["plugin-info"]["id"]  # Unique identifier used to register challenges
    name = settings["plugin-info"]["name"]  # Name of a challenge type
    templates =  settings["plugin-info"]["templates"] # Handlebars templates used for each aspect of challenge editing & viewing
    scripts = settings["plugin-info"]["scripts"] # Scripts that are loaded when a template is loaded
    # Route at which files are accessible. This must be registered using register_plugin_assets_directory()
    route = "/plugins/containers/assets/"

    challenge_model = ContainerChallengeModel
    
    @classmethod
    def read(cls, challenge):
        """
        This method is in used to access the data of a challenge in a format processable by the front end.

        :param challenge:
        :return: Challenge object, data dictionary to be returned to the user
        """
        data = {
            "id": challenge.id,
            "name": challenge.name,
            "value": challenge.value,
            "image": challenge.image,
            "port": challenge.port,
            "command": challenge.command,
            "ctype": challenge.ctype,
            "ssh_username": challenge.ssh_username,
            "ssh_password": challenge.ssh_password,
            "initial": challenge.initial,
            "decay": challenge.decay,
            "minimum": challenge.minimum,
            "description": challenge.description,
            "connection_info": challenge.connection_info,
            "category": challenge.category,
            "state": challenge.state,
            "max_attempts": challenge.max_attempts,
            "type": challenge.type,
            "type_data": {
                "id": cls.id,
                "name": cls.name,
                "templates": cls.templates,
                "scripts": cls.scripts,
            },
        }
        return data

    @classmethod
    def calculate_value(cls, challenge):
        Model = get_model()

        solve_count = (
            Solves.query.join(Model, Solves.account_id == Model.id)
            .filter(
                Solves.challenge_id == challenge.id,
                Model.hidden == False,
                Model.banned == False,
            )
            .count()
        )

        # If the solve count is 0 we shouldn't manipulate the solve count to
        # let the math update back to normal
        if solve_count != 0:
            # We subtract -1 to allow the first solver to get max point value
            solve_count -= 1

        # It is important that this calculation takes into account floats.
        # Hence this file uses from __future__ import division
        value = (
            ((challenge.minimum - challenge.initial) / (challenge.decay ** 2))
            * (solve_count ** 2)
        ) + challenge.initial

        value = math.ceil(value)

        if value < challenge.minimum:
            value = challenge.minimum

        challenge.value = value
        db.session.commit()
        return challenge

    @classmethod
    def update(cls, challenge, request):
        """
        This method is used to update the information associated with a challenge. This should be kept strictly to the
        Challenges table and any child tables.
        :param challenge:
        :param request:
        :return:
        """
        data = request.form or request.get_json()

        for attr, value in data.items():
            # We need to set these to floats so that the next operations don't operate on strings
            if attr in ("initial", "minimum", "decay"):
                value = float(value)
            setattr(challenge, attr, value)

        return ContainerChallenge.calculate_value(challenge)

    @classmethod
    def solve(cls, user, team, challenge, request):
        super().solve(user, team, challenge, request)

        ContainerChallenge.calculate_value(challenge)


def settings_to_dict(settings):
    return {
        setting.key: setting.value for setting in settings
    }

def is_team_mode():
    mode = get_config("user_mode")
    if mode == TEAMS_MODE:
        return True
    elif mode == USERS_MODE:
        return False
    else:
        return None

def load(app: Flask):
    app.db.create_all()
    CHALLENGE_CLASSES["container"] = ContainerChallenge
    register_plugin_assets_directory(
        app, base_path="/plugins/containers/assets/"
    )

    container_settings = settings_to_dict(ContainerSettingsModel.query.all())
    container_manager = ContainerManager(container_settings, app)

    containers_bp = Blueprint(
        'containers', __name__, template_folder='templates', static_folder='assets', url_prefix='/containers')

    @containers_bp.app_template_filter("format_time")
    def format_time_filter(unix_seconds):
        dt = datetime.datetime.fromtimestamp(unix_seconds, tz=datetime.datetime.now(
            datetime.timezone.utc).astimezone().tzinfo)
        return dt.strftime("%H:%M:%S %d/%m/%Y")

    def kill_container(container_id):
        container: ContainerInfoModel = ContainerInfoModel.query.filter_by(
            container_id=container_id).first()

        try:
            container_manager.kill_container(container_id)
        except ContainerException:
            return {"error": "Docker is not initialized. Please check your settings."}

        db.session.delete(container)

        db.session.commit()
        return {"success": "Container killed"}

    def renew_container(chal_id, xid, is_team):
        # Get the requested challenge
        challenge = ContainerChallenge.challenge_model.query.filter_by(
            id=chal_id).first()

        # Make sure the challenge exists and is a container challenge
        if challenge is None:
            return {"error": "Challenge not found"}, 400

        if is_team is True:
            running_containers = ContainerInfoModel.query.filter_by(
            challenge_id=challenge.id, team_id=xid)
        else:
            running_containers = ContainerInfoModel.query.filter_by(
            challenge_id=challenge.id, user_id=xid)
        running_container = running_containers.first()

        if running_container is None:
            return {"error": "Container not found, try resetting the container."}

        try:
            running_container.expires = int(
                time.time() + container_manager.expiration_seconds)
            db.session.commit()
        except ContainerException:
            return {"error": "Database error occurred, please try again."}

        return {"success": "Container renewed", "expires": running_container.expires, "hostname": container_manager.settings.get("docker_hostname", ""), "port": running_container.port, "connect": challenge.ctype}

    def create_container(chal_id, xid, uid, is_team):
        # Get the requested challenge
        challenge = ContainerChallenge.challenge_model.query.filter_by(
            id=chal_id).first()

        # Make sure the challenge exists and is a container challenge
        if challenge is None:
            return {"error": "Challenge not found"}, 400

        # Check if user already has MAX_CONTAINERS_ALLOWED number running containers.
        MAX_CONTAINERS_ALLOWED = settings["vars"]["MAX_CONTAINERS_ALLOWED"]
        if not is_team: uid = xid
        t_containers = ContainerInfoModel.query.filter_by(
            user_id=uid)

        if t_containers.count() >= MAX_CONTAINERS_ALLOWED:
            return { "error": f"You can only spawn {MAX_CONTAINERS_ALLOWED} containers at a time. Please stop other containers to continue" }, 500

        # Check for any existing containers for the team
        if is_team is True:
            running_containers = ContainerInfoModel.query.filter_by(
                challenge_id=challenge.id, team_id=xid)
        else:
            running_containers = ContainerInfoModel.query.filter_by(
                challenge_id=challenge.id, user_id=xid)           
        running_container = running_containers.first()

        # If a container is already running for the team, return it
        if running_container:
            # Check if Docker says the container is still running before returning it
            try:
                if container_manager.is_container_running(
                        running_container.container_id):
                    return json.dumps({
                        "status": "already_running",
                        "hostname": container_manager.settings.get("docker_hostname", ""),
                        "port": running_container.port,
                        "ssh_username": running_container.ssh_username,
                        "ssh_password": running_container.ssh_password,
                        "connect": challenge.ctype,
                        "expires": running_container.expires
                    })
                else:
                    # Container is not running, it must have died or been killed,
                    # remove it from the database and create a new one
                    running_containers.delete()
                    db.session.commit()
            except ContainerException as err:
                return {"error": str(err)}, 500

        # Run a new Docker container
        try:
            created_container = container_manager.create_container(
                chal_id, xid, uid, challenge.image, challenge.port, challenge.command, challenge.volumes)
        except ContainerException as err:
            return {"error": str(err)}

        # Fetch the random port Docker assigned
        port = container_manager.get_container_port(created_container.id)

        # Port may be blank if the container failed to start
        if port is None:
            return json.dumps({
                "status": "error",
                "error": "Could not get port"
            })

        expires = int(time.time() + container_manager.expiration_seconds)

        # Insert the new container into the database
        if is_team is True:
            new_container = ContainerInfoModel(
                container_id=created_container.id,
                challenge_id=challenge.id,
                team_id=xid,
                user_id=uid,
                port=port,
                timestamp=int(time.time()),
                expires=expires
            )
        else: 
            new_container = ContainerInfoModel(
                container_id=created_container.id,
                challenge_id=challenge.id,
                user_id=xid,
                port=port,
                timestamp=int(time.time()),
                expires=expires
            )
        db.session.add(new_container)
        db.session.commit()

        return json.dumps({
            "status": "created",
            "hostname": container_manager.settings.get("docker_hostname", ""),
            "port": port,
            "connect": challenge.ctype,
            "expires": expires
        })

    def view_container_info(chal_id, xid, is_team):
        # Get the requested challenge
        challenge = ContainerChallenge.challenge_model.query.filter_by(
            id=chal_id).first()

        # Make sure the challenge exists and is a container challenge
        if challenge is None:
            return {"error": "Challenge not found"}, 400

        # Check for any existing containers for the team
        if is_team is True:
            running_containers = ContainerInfoModel.query.filter_by(
                challenge_id=challenge.id, team_id=xid)
        else:
            running_containers = ContainerInfoModel.query.filter_by(
                challenge_id=challenge.id, user_id=xid)
        running_container = running_containers.first()

        # If a container is already running for the team, return it
        if running_container:
            # Check if Docker says the container is still running before returning it
            try:
                if container_manager.is_container_running(
                        running_container.container_id):
                    return json.dumps({
                        "status": "already_running",
                        "hostname": container_manager.settings.get("docker_hostname", ""),
                        "port": running_container.port,
                        "connect": challenge.ctype,
                        "expires": running_container.expires
                    })
                else:
                    # Container is not running, it must have died or been killed,
                    # remove it from the database and create a new one
                    running_containers.delete()
                    db.session.commit()
            except ContainerException as err:
                return {"error": str(err)}, 500
        else:
            return {"status": "Suffering hasn't begun"}

    def connect_type(chal_id):
        # Get the requested challenge
        challenge = ContainerChallenge.challenge_model.query.filter_by(
            id=chal_id).first()

        # Make sure the challenge exists and is a container challenge
        if challenge is None:
            return {"error": "Challenge not found"}, 400

        return json.dumps({
                        "status": "Ok",
                        "connect": challenge.ctype
                    })

    @containers_bp.route('/api/get_connect_type/<int:challenge_id>', methods=['GET'])
    @authed_only
    @during_ctf_time_only
    @require_verified_emails
    @ratelimit(method="GET", limit=settings["requests"]["limit"], interval=settings["requests"]["limit"])
    def get_connect_type(challenge_id):
        try:
            return connect_type(challenge_id)
        except ContainerException as err:
            return {"error": str(err)}, 500

    @containers_bp.route('/api/view_info', methods=['POST'])
    @authed_only
    @during_ctf_time_only
    @require_verified_emails
    @ratelimit(method="POST", limit=settings["requests"]["limit"], interval=settings["requests"]["limit"])
    def route_view_info():
        user = get_current_user()

        # Validate the request
        if request.json is None:
            return {"error": "Invalid request"}, 400

        if request.json.get("chal_id", None) is None:
            return {"error": "No chal_id specified"}, 400

        if user is None:
            return {"error": "User not found"}, 400
        if user.team is None and is_team_mode() is True:
            return {"error": "User not a member of a team"}, 400

        try:
            if is_team_mode() is True:
                return view_container_info(request.json.get("chal_id"), user.team.id, True)
            elif is_team_mode() is False:
                return view_container_info(request.json.get("chal_id"), user.id, False)
        except ContainerException as err:
            return {"error": str(err)}, 500

    @containers_bp.route('/api/request', methods=['POST'])
    @authed_only
    @during_ctf_time_only
    @require_verified_emails
    @ratelimit(method="POST", limit=settings["requests"]["limit"], interval=settings["requests"]["limit"])
    def route_request_container():
        user = get_current_user()

        # Validate the request
        if request.json is None:
            return {"error": "Invalid request"}, 400

        if request.json.get("chal_id", None) is None:
            return {"error": "No chal_id specified"}, 400

        if user is None:
            return {"error": "User not found"}, 400
        if user.team is None and is_team_mode() is True:
            return {"error": "User not a member of a team"}, 400

        try:
            if is_team_mode() is True:
                return create_container(request.json.get("chal_id"), user.team.id, user.id,True)
            elif is_team_mode() is False:
                return create_container(request.json.get("chal_id"), user.id, user.id, False)   
        except ContainerException as err:
            return {"error": str(err)}, 500

    @containers_bp.route('/api/renew', methods=['POST'])
    @authed_only
    @during_ctf_time_only
    @require_verified_emails
    @ratelimit(method="POST", limit=settings["requests"]["limit"], interval=settings["requests"]["limit"])
    def route_renew_container():
        user = get_current_user()

        # Validate the request
        if request.json is None:
            return {"error": "Invalid request"}, 400

        if request.json.get("chal_id", None) is None:
            return {"error": "No chal_id specified"}, 400

        if user is None:
            return {"error": "User not found"}, 400
        if user.team is None and is_team_mode() is True:
            return {"error": "User not a member of a team"}, 400

        try:
            if is_team_mode() is True:
                return renew_container(request.json.get("chal_id"), user.team.id, True)
            elif is_team_mode() is False:
                return renew_container(request.json.get("chal_id"), user.id, False)
        except ContainerException as err:
            return {"error": str(err)}, 500

        user = get_current_user()

        # Validate the request
        if request.json is None:
            return {"error": "Invalid request"}, 400

        if request.json.get("chal_id", None) is None:
            return {"error": "No chal_id specified"}, 400

        if user is None:
            return {"error": "User not found"}, 400
        if user.team is None and is_team_mode() is True:
            return {"error": "User not a member of a team"}, 400

        if is_team_mode() is True:
            running_container: ContainerInfoModel = ContainerInfoModel.query.filter_by(
                challenge_id=request.json.get("chal_id"), team_id=user.team.id).first()

            if running_container:
                kill_container(running_container.container_id)

            return create_container(request.json.get("chal_id"), user.team.id, user.id, True)
        elif is_team_mode() is False:
            running_container: ContainerInfoModel = ContainerInfoModel.query.filter_by(
                challenge_id=request.json.get("chal_id"), team_id=user.id).first()

            if running_container:
                kill_container(running_container.container_id)

            return create_container(request.json.get("chal_id"), user.id, None, False)

    @containers_bp.route('/api/stop', methods=['POST'])
    @authed_only
    @during_ctf_time_only
    @require_verified_emails
    @ratelimit(method="POST", limit=settings["requests"]["limit"], interval=settings["requests"]["limit"])
    def route_stop_container():
        user = get_current_user()

        # Validate the request
        if request.json is None:
            return {"error": "Invalid request"}, 400

        if request.json.get("chal_id", None) is None:
            return {"error": "No chal_id specified"}, 400

        if user is None:
            return {"error": "User not found"}, 400
        if user.team is None and is_team_mode() is True:
            return {"error": "User not a member of a team"}, 400

        if is_team_mode() is True:
            running_container: ContainerInfoModel = ContainerInfoModel.query.filter_by(
                challenge_id=request.json.get("chal_id"), team_id=user.team.id).first()

            if running_container:
                return kill_container(running_container.container_id)

            return {"error": "No container found"}, 400
        elif is_team_mode() is False:
            running_container: ContainerInfoModel = ContainerInfoModel.query.filter_by(
                challenge_id=request.json.get("chal_id"), user_id=user.id).first()

            if running_container:
                return kill_container(running_container.container_id)

            return {"error": "No container found"}, 400


    @containers_bp.route('/api/kill', methods=['POST'])
    @admins_only
    def route_kill_container():
        if request.json is None:
            return {"error": "Invalid request"}, 400

        if request.json.get("container_id", None) is None:
            return {"error": "No container_id specified"}, 400

        return kill_container(request.json.get("container_id"))

    @containers_bp.route('/api/purge', methods=['POST'])
    @admins_only
    def route_purge_containers():
        containers: "list[ContainerInfoModel]" = ContainerInfoModel.query.all()
        for container in containers:
            try:
                kill_container(container.container_id)
            except ContainerException:
                pass
        return {"success": "Purged all containers"}, 200

    @containers_bp.route('/api/images', methods=['GET'])
    @admins_only
    def route_get_images():
        try:
            images = container_manager.get_images()
        except ContainerException as err:
            return {"error": str(err)}

        return {"images": images}

    @containers_bp.route('/api/settings/update', methods=['POST'])
    @admins_only
    def route_update_settings():
        if request.form.get("docker_base_url") is None:
            return {"error": "Invalid request"}, 400

        if request.form.get("docker_hostname") is None:
            return {"error": "Invalid request"}, 400

        if request.form.get("container_expiration") is None:
            return {"error": "Invalid request"}, 400

        if request.form.get("container_maxmemory") is None:
            return {"error": "Invalid request"}, 400

        if request.form.get("container_maxcpu") is None:
            return {"error": "Invalid request"}, 400

        docker_base_url = ContainerSettingsModel.query.filter_by(
            key="docker_base_url").first()

        docker_hostname = ContainerSettingsModel.query.filter_by(
            key="docker_hostname").first()

        container_expiration = ContainerSettingsModel.query.filter_by(
            key="container_expiration").first()

        container_maxmemory = ContainerSettingsModel.query.filter_by(
            key="container_maxmemory").first()

        container_maxcpu = ContainerSettingsModel.query.filter_by(
            key="container_maxcpu").first()

        # Create or update
        if docker_base_url is None:
            # Create
            docker_base_url = ContainerSettingsModel(
                key="docker_base_url", value=request.form.get("docker_base_url"))
            db.session.add(docker_base_url)
        else:
            # Update
            docker_base_url.value = request.form.get("docker_base_url")

        # Create or update
        if docker_hostname is None:
            # Create
            docker_hostname = ContainerSettingsModel(
                key="docker_hostname", value=request.form.get("docker_hostname"))
            db.session.add(docker_hostname)
        else:
            # Update
            docker_hostname.value = request.form.get("docker_hostname")

        # Create or update
        if container_expiration is None:
            # Create
            container_expiration = ContainerSettingsModel(
                key="container_expiration", value=request.form.get("container_expiration"))
            db.session.add(container_expiration)
        else:
            # Update
            container_expiration.value = request.form.get(
                "container_expiration")

        # Create or update
        if container_maxmemory is None:
            # Create
            container_maxmemory = ContainerSettingsModel(
                key="container_maxmemory", value=request.form.get("container_maxmemory"))
            db.session.add(container_maxmemory)
        else:
            # Update
            container_maxmemory.value = request.form.get("container_maxmemory")

        # Create or update
        if container_maxcpu is None:
            # Create
            container_maxcpu = ContainerSettingsModel(
                key="container_maxcpu", value=request.form.get("container_maxcpu"))
            db.session.add(container_maxcpu)
        else:
            # Update
            container_maxcpu.value = request.form.get("container_maxcpu")

        db.session.commit()

        container_manager.settings = settings_to_dict(
            ContainerSettingsModel.query.all())

        if container_manager.settings.get("docker_base_url") is not None:
            try:
                container_manager.initialize_connection(
                    container_manager.settings, app)
            except ContainerException as err:
                flash(str(err), "error")
                return redirect(url_for(".route_containers_settings"))

        return redirect(url_for(".route_containers_dashboard"))

    @containers_bp.route('/dashboard', methods=['GET'])
    @admins_only
    def route_containers_dashboard():
        running_containers = ContainerInfoModel.query.order_by(
            ContainerInfoModel.timestamp.desc()).all()

        connected = False
        try:
            connected = container_manager.is_connected()
        except ContainerException:
            pass

        for i, container in enumerate(running_containers):
            try:
                running_containers[i].is_running = container_manager.is_container_running(
                    container.container_id)
            except ContainerException:
                running_containers[i].is_running = False

        return render_template('container_dashboard.html', containers=running_containers, connected=connected)

    @containers_bp.route('/api/running_containers', methods=['GET'])
    @admins_only
    def route_get_running_containers():
        running_containers = ContainerInfoModel.query.order_by(
            ContainerInfoModel.timestamp.desc()).all()

        connected = False
        try:
            connected = container_manager.is_connected()
        except ContainerException:
            pass

        # Create lists to store unique teams and challenges
        unique_teams = set()
        unique_challenges = set()

        for i, container in enumerate(running_containers):
            try:
                running_containers[i].is_running = container_manager.is_container_running(
                    container.container_id)
            except ContainerException:
                running_containers[i].is_running = False

            # Add team and challenge to the unique sets
            if is_team_mode() is True:
                unique_teams.add(f"{container.team.name} [{container.team_id}]")
            else:   
                unique_teams.add(f"{container.user.name} [{container.user_id}]")
            unique_challenges.add(f"{container.challenge.name} [{container.challenge_id}]")

        # Convert unique sets to lists
        unique_teams_list = list(unique_teams)
        unique_challenges_list = list(unique_challenges)

        # Create a list of dictionaries containing running_containers data
        running_containers_data = []
        for container in running_containers:
            if is_team_mode() is True:
                container_data = {
                    "container_id": container.container_id,
                    "image": container.challenge.image,
                    "challenge": f"{container.challenge.name} [{container.challenge_id}]",
                    "team": f"{container.team.name} [{container.team_id}]",
                    "user": f"{container.user.name} [{container.user_id}]",
                    "port": container.port,
                    "created": container.timestamp,
                    "expires": container.expires,
                    "is_running": container.is_running
                }
            else:
                container_data = {
                    "container_id": container.container_id,
                    "image": container.challenge.image,
                    "challenge": f"{container.challenge.name} [{container.challenge_id}]",
                    "user": f"{container.user.name} [{container.user_id}]",
                    "port": container.port,
                    "created": container.timestamp,
                    "expires": container.expires,
                    "is_running": container.is_running
                }
            running_containers_data.append(container_data)

        # Create a JSON response containing running_containers_data, unique teams, and unique challenges
        response_data = {
            "containers": running_containers_data,
            "connected": connected,
            "teams": unique_teams_list,
            "challenges": unique_challenges_list
        }

        # Return the JSON response
        return json.dumps(response_data)


    @containers_bp.route('/settings', methods=['GET'])
    @admins_only
    def route_containers_settings():
        running_containers = ContainerInfoModel.query.order_by(
            ContainerInfoModel.timestamp.desc()).all()
        return render_template('container_settings.html', settings=container_manager.settings)

    app.register_blueprint(containers_bp)
