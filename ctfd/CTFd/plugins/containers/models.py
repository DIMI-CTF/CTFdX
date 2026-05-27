from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from CTFd.models import db
from CTFd.models import Challenges


class ContainerChallengeModel(Challenges):
    __mapper_args__ = {"polymorphic_identity": "container"}
    id = db.Column(
        db.Integer, db.ForeignKey("challenges.id", ondelete="CASCADE"), primary_key=True
    )
    image = db.Column(db.Text)
    port = db.Column(db.Integer)
    command = db.Column(db.Text, default="")
    volumes = db.Column(db.Text, default="")
    ctype = db.Column(db.Text, default="tcp")

    ssh_username = db.Column(db.Text, nullable=True)
    ssh_password = db.Column(db.Text, nullable=True)

    # Dynamic challenge properties
    initial = db.Column(db.Integer, default=0)
    minimum = db.Column(db.Integer, default=0)
    decay = db.Column(db.Integer, default=0)

    def __init__(self, *args, **kwargs):
        super(ContainerChallengeModel, self).__init__(**kwargs)
        self.value = kwargs["initial"]


class ContainerInfoModel(db.Model):
    __mapper_args__ = {"polymorphic_identity": "container_info"}
    container_id = db.Column(db.String(512), primary_key=True)
    challenge_id = db.Column(
        db.Integer, db.ForeignKey("challenges.id", ondelete="CASCADE")
    )
    team_id = db.Column(
        db.Integer, db.ForeignKey("teams.id", ondelete="CASCADE")
    )
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE")
    )
    port = db.Column(db.Integer)
    ssh_username = db.Column(db.Text, nullable=True)
    ssh_password = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.Integer)
    expires = db.Column(db.Integer)
    team = relationship("Teams", foreign_keys=[team_id])
    user = relationship("Users", foreign_keys=[user_id])
    challenge = relationship(ContainerChallengeModel,
                             foreign_keys=[challenge_id])

class ContainerSettingsModel(db.Model):
    __mapper_args__ = {"polymorphic_identity": "container_settings"}
    key = db.Column(db.String(512), primary_key=True)
    value = db.Column(db.Text)
