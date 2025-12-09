import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = 'questa-è-una-chiave-super-sicura-cambia-pure-se-vuoi'

    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'instance', 'users.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PROXMOX_HOST = 'https://192.168.56.15:8006'
    PROXMOX_NODE = 'px1'
    PROXMOX_USER = 'root@pam'
    PROXMOX_PASSWORD = 'Password&1'
    PROXMOX_VERIFY_SSL = False
