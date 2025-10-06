# ScanShield

ScanShield est une application conçue pour l'extraction et l'analyse de fonctionnalités à partir de fichiers, avec une interface Python et une structure modulaire.

## Fonctionnalités principales
- Extraction de caractéristiques à partir de fichiers
- Analyse automatisée
- Gestion des utilisateurs (base de données SQLite)
- Journalisation des activités
- Conteneurisation avec Docker

## Structure du projet
```
scanshield/
	 app.py                  # Point d'entrée principal de l'application
	 extractorFunctions.py   # Fonctions d'extraction de caractéristiques
	 featureExtractor.py     # Logique d'extraction de features
	 main.py                 # Script principal (peut-être pour le lancement)
	 requirements.txt        # Dépendances Python
	 Dockerfile              # Conteneurisation Docker
	 users.db                # Base de données SQLite pour les utilisateurs
	 logs.log                # Fichier de logs
```

## Installation
1. Clonez le dépôt :
	```bash
	git clone <url-du-repo>
	cd ScanSheild
	```
2. Installez les dépendances :
	```bash
	pip install -r scanshield/requirements.txt
	```
3. (Optionnel) Construisez et lancez avec Docker :
	```bash
	docker build -t scanshield ./scanshield
	docker run -p 5000:5000 scanshield
	```

## Utilisation
- Lancez l'application :
  ```bash
  python scanshield/app.py
  ```
- Consultez les logs dans `scanshield/logs.log`.
- La base de données utilisateurs est stockée dans `scanshield/users.db`.

## Contribution
Les contributions sont les bienvenues !

## Licence
Ce projet est sous licence MIT.
