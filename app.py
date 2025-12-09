from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, VMRequest
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_tables():
    if not hasattr(app, 'tables_created'):
        db.create_all()

        # Utenti di test (solo se non esistono già)
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin',
                         password=generate_password_hash('admin&1'),
                         is_admin=True)
            smane = User(username='smane',
                         password=generate_password_hash('Smane&1'),
                         is_admin=False)
            luigi = User(username='luigi',
                         password=generate_password_hash('Luigi&1'),
                         is_admin=False)
            db.session.add(admin)
            db.session.add(smane)
            db.session.add(luigi)
            db.session.commit()

        app.tables_created = True

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
        else:
            flash('Username o password errati', 'danger')

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
            flash('Richiesta inviata correttamente! Attendi l’approvazione.', 'success')
            return redirect(url_for('dashboard'))

    return render_template('request_vm.html')


@app.route('/admin/approve/<int:req_id>')
@login_required
def approve_request(req_id):
    if not current_user.is_admin:
        flash('Accesso negato')
        return redirect(url_for('dashboard'))

    req = VMRequest.query.get_or_404(req_id)
    req.status = 'approved'

    req.vm_id = 10000 + req_id
    req.ip_address = f"10.0.0.{50 + req_id}"
    req.password = "SuperPassword123!"

    db.session.commit()
    flash(f'Richiesta #{req_id} approvata e VM creata (simulata)', 'success')
    return redirect(url_for('dashboard'))


@app.route('/admin/reject/<int:req_id>')
@login_required
def reject_request(req_id):
    if not current_user.is_admin:
        flash('Accesso negato')
        return redirect(url_for('dashboard'))

    req = VMRequest.query.get_or_404(req_id)
    req.status = 'rejected'
    db.session.commit()
    flash(f'Richiesta #{req_id} rifiutata', 'info')
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run(debug=True, port=5000)