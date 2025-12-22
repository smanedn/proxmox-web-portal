# proxmox-web-portal

<img src="https://www.snel.com/wp-content/uploads/proxmox-logo-color-stacked.png" alt="Proxmox Logo" width="200"/>

Portale web Flask per richiedere e creare VM su Proxmox VE.

## Funzionalità
- Login utenti (con ruolo admin/utente)
- Richiesta VM tra 3 livelli: Bronze (1 core, 1GB), Silver (2 core, 2GB), Gold (4 core, 4GB)
- Approvazione/rifiuto da parte dell'admin
- Creazione automatica VM (clone da template 9000, Cloud-Init, avvio)
- Recupero IP via Guest Agent e password casuale
- Dashboard con stato richieste e credenziali

## Utenti di test (creati al primo avvio)
- admin → admin&1 (amministratore)
- smane → Smane&1
- luigi → Luigi&1

## Prerequisiti
- Template VM con ID 9000 (Cloud-Init + QEMU Guest Agent)
- Proxmox raggiungibile con credenziali in `config.py`

## Installazione
- Avviare tutti i nodi su Proxmox
- Avviare la macchina che contiene il progetto Web
- Avviare il servizio web / In caso mancante clonare dal github e installare i requisiti tramite il "requirements.txt"

```bash
python app.py