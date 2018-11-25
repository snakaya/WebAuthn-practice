from db import db
from datetime import datetime


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    ukey = db.Column(db.String(20), unique=False, nullable=False)
    credential_id = db.Column(db.Text, unique=False, nullable=False)
    display_name = db.Column(db.String(160), unique=False, nullable=True)
    pub_key = db.Column(db.Text, unique=False, nullable=True)
    sign_count = db.Column(db.Integer, default=0)
    username = db.Column(db.String(80), unique=False, nullable=False)
    att_option = db.Column(db.Text, nullable=True)
    response = db.Column(db.Text, nullable=True)
    response_dec = db.Column(db.Text, nullable=True)
    rp_id = db.Column(db.String(253), nullable=False)
    icon_url = db.Column(db.String(2083), nullable=True)
    created = db.Column(db.DateTime, default=datetime.now())

    def to_dict(self):
        return dict(
            id=self.id,
            ukey=self.ukey,
            credential_id=self.credential_id,
            display_name=self.display_name,
            pub_key=self.pub_key,
            sign_count = self.sign_count,
            username=self.username,
            att_option = self.att_option,
            response = self.response,
            response_dec = self.response_dec,
            rp_id = self.rp_id,
            icon_url = self.icon_url,
            created = self.created
        )

    def __repr__(self):
        return '<User %r %r>' % (self.display_name, self.username)


class Options(db.Model):
    rp_id = db.Column(db.String(253), primary_key=True)
    version = db.Column(db.Integer, default=0)
    option_content = db.Column(db.Text, unique=False, nullable=False)

    def __repr__(self):
        return '<Options RP=%r, version=%r>' % (self.rp_id, self.version)
