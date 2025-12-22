from flask import Flask, render_template, request, redirect, url_for, flash, g
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, VMRequest
from config import Config
from proxmoxer import ProxmoxAPI
import random, string, time

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

init_done = False

@app.before_request
def create_tables_and_users():
    global init_done
    if not init_done:
        db.create_all()
        if User.query.count() == 0:
            admin = User(username='admin', password=generate_password_hash('admin&1'), is_admin=True)
            smane = User(username='smane', password=generate_password_hash('Smane&1'), is_admin=False)
            luigi = User(username='luigi', password=generate_password_hash('Luigi&1'), is_admin=False)
            db.session.add_all([admin, smane, luigi])
            db.session.commit()
            print("\nUtenti di test creati:")
            print("   → admin    / admin&1")
            print("   → smane    / Smane&1")
            print("   → luigi    / Luigi&1\n")

        init_done = True

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Credenziali errate', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        requests = VMRequest.query.all()
        return render_template('admin_requests.html', requests=requests)
    else:
        my_requests = VMRequest.query.filter_by(user_id=current_user.id).all()
        return render_template('dashboard.html', requests=my_requests)

@app.route('/request_vm', methods=['GET', 'POST'])
@login_required
def request_vm():
    if current_user.is_admin:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        vm_type = request.form['vm_type']
        if vm_type in ['bronze', 'silver', 'gold']:
            nuova = VMRequest(user_id=current_user.id, vm_type=vm_type)
            db.session.add(nuova)
            db.session.commit()
            flash('Richiesta inviata! Attendi approvazione.', 'success')
            return redirect(url_for('dashboard'))
    return render_template('request_vm.html')

@app.route('/admin/approve/<int:req_id>')
@login_required
def approve_request(req_id):
    if not current_user.is_admin:
        flash('Accesso negato', 'danger')
        return redirect(url_for('dashboard'))

    req = VMRequest.query.get_or_404(req_id)
    if req.status != 'pending':
        flash('Richiesta già gestita', 'warning')
        return redirect(url_for('dashboard'))

    try:
        proxmox = ProxmoxAPI(
            Config.PROXMOX_HOST.replace('https://', '').replace('http://', '').split(':')[0],
            user=Config.PROXMOX_USER,
            password=Config.PROXMOX_PASSWORD,
            port=8006,
            verify_ssl=Config.PROXMOX_VERIFY_SSL,
            timeout=180
        )

        risorse = {
            'bronze': {'cores': 1, 'memory': 1024},
            'silver': {'cores': 2, 'memory': 2048},
            'gold':   {'cores': 4, 'memory': 4096}
        }[req.vm_type]

        password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        new_vmid = 10000 + req.id

        proxmox.nodes(Config.PROXMOX_NODE).qemu(9000).clone.post(
            newid=new_vmid,
            name=f"portale-{req.user.username}-{req.id}",
            full=1,
            target=Config.PROXMOX_NODE
        )

        proxmox.nodes(Config.PROXMOX_NODE).qemu(new_vmid).config.post(
            cores=risorse['cores'],
            memory=risorse['memory'],
            cipassword=password,
            ciuser='root',
            ipconfig0='ip=dhcp'
        )

        proxmox.nodes(Config.PROXMOX_NODE).qemu(new_vmid).status.start.post()

        time.sleep(12)
        ip = "IP non ancora disponibile (attendi 30s)"
        try:
            proxmox_ip = ProxmoxAPI(
                Config.PROXMOX_HOST.replace('https://', '').replace('http://', '').split(':')[0],
                user=Config.PROXMOX_USER,
                password=Config.PROXMOX_PASSWORD,
                port=8006,
                verify_ssl=Config.PROXMOX_VERIFY_SSL,
                timeout=240
            )
            net = proxmox_ip.nodes(Config.PROXMOX_NODE).qemu(new_vmid).agent('network-get-interfaces').get()
            for iface in net['result']:
                if 'ip-addresses' in iface:
                    for addr in iface['ip-addresses']:
                        if addr.get('ip-address-type') == 'ipv4' and not addr['ip-address'].startswith('127'):
                            ip = addr['ip-address']
                            break
                    if ip != "IP non ancora disponibile (attendi 30s)":
                        break
        except Exception as e:
            print("Impossibile leggere IP:", e)

        req.status = 'approved'
        req.vm_id = new_vmid
        req.ip_address = ip
        req.password = password
        db.session.commit()

        flash(f'VM CREATA! → ID {new_vmid} | IP: {ip} | Pass: {password}', 'success')

    except Exception as e:
        req.status = 'rejected'
        db.session.commit()
        flash(f'Errore creazione VM: {str(e)}', 'danger')
        print("Errore Proxmox:", e)

    return redirect(url_for('dashboard'))

@app.route('/admin/reject/<int:req_id>')
@login_required
def reject_request(req_id):
    if not current_user.is_admin:
        flash('Accesso negato', 'danger')
        return redirect(url_for('dashboard'))

    req = VMRequest.query.get_or_404(req_id)
    if req.status != 'pending':
        flash('Richiesta già gestita', 'warning')
        return redirect(url_for('dashboard'))

    req.status = 'rejected'
    db.session.commit()
    flash(f'Richiesta #{req_id} rifiutata', 'info')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)