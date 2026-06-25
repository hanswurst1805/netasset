# NetAsset auf Kubernetes (Anleitung)

Empfohlen für Einzel-Host-Betrieb ist Podman (`scripts/deploy.sh`) oder Docker
(`scripts/docker_start.sh`). Für Cluster-Betrieb beschreibt dieses Dokument eine
funktionierende Referenz-Topologie. Die Manifeste sind ein **Startpunkt** –
Ressourcen-Limits, Storage-Class und Ingress an eure Umgebung anpassen.

## Bestandteile

| Komponente | Kubernetes-Objekt |
|---|---|
| PostgreSQL 16 + pgvector | StatefulSet + Service + PVC |
| API (FastAPI) | Deployment + Service |
| DB-Migration (Alembic) | Job (vor/zum Rollout) |
| Frontend (React SPA) | Deployment + Service (statisches Image) |
| TLS / Routing | Ingress (cert-manager) |
| Secrets / Config | Secret + ConfigMap |

## Image bauen & in die Registry

```bash
# API-Image (enthält FastAPI + Migrationen)
docker build -t registry.example.com/netasset/api:1.0 .
docker push registry.example.com/netasset/api:1.0

# Frontend als statisches Image (Caddy/nginx mit gebautem dist)
cd dashboard && npm ci && npm run build && cd ..
cat > Dockerfile.web <<'EOF'
FROM caddy:2-alpine
COPY dashboard/dist /srv
RUN printf ':80 {\n  root * /srv\n  try_files {path} /index.html\n  file_server\n}\n' > /etc/caddy/Caddyfile
EOF
docker build -f Dockerfile.web -t registry.example.com/netasset/web:1.0 .
docker push registry.example.com/netasset/web:1.0
```

## 1. Namespace, Secret, Config

```yaml
apiVersion: v1
kind: Namespace
metadata: { name: netasset }
---
apiVersion: v1
kind: Secret
metadata: { name: netasset-secrets, namespace: netasset }
stringData:
  DB_PASSWORD: "CHANGE_ME_STRONG"
  JWT_SECRET: "CHANGE_ME_32+_RANDOM"
  INITIAL_ADMIN_PASSWORD: "CHANGE_ME"
  OPENROUTER_API_KEY: "sk-or-v1-..."
  NVD_API_KEY: ""
---
apiVersion: v1
kind: ConfigMap
metadata: { name: netasset-config, namespace: netasset }
data:
  LLM_MODEL: "anthropic/claude-sonnet-4-5"
  EMBEDDING_MODEL: "all-MiniLM-L6-v2"
  LOG_LEVEL: "INFO"
```

## 2. PostgreSQL (pgvector)

```yaml
apiVersion: v1
kind: Service
metadata: { name: db, namespace: netasset }
spec:
  selector: { app: db }
  ports: [{ port: 5432, targetPort: 5432 }]
---
apiVersion: apps/v1
kind: StatefulSet
metadata: { name: db, namespace: netasset }
spec:
  serviceName: db
  replicas: 1
  selector: { matchLabels: { app: db } }
  template:
    metadata: { labels: { app: db } }
    spec:
      containers:
        - name: db
          image: pgvector/pgvector:pg16
          env:
            - { name: POSTGRES_DB, value: netasset }
            - { name: POSTGRES_USER, value: netasset }
            - name: POSTGRES_PASSWORD
              valueFrom: { secretKeyRef: { name: netasset-secrets, key: DB_PASSWORD } }
          ports: [{ containerPort: 5432 }]
          volumeMounts: [{ name: pgdata, mountPath: /var/lib/postgresql/data }]
          readinessProbe:
            exec: { command: ["pg_isready", "-U", "netasset"] }
            initialDelaySeconds: 10
            periodSeconds: 10
  volumeClaimTemplates:
    - metadata: { name: pgdata }
      spec:
        accessModes: ["ReadWriteOnce"]
        resources: { requests: { storage: 10Gi } }
        # storageClassName: <eure-storage-class>
```

## 3. Migration (Job)

Vor jedem Rollout (oder als Helm `pre-install`/`pre-upgrade`-Hook) ausführen:

```yaml
apiVersion: batch/v1
kind: Job
metadata: { name: netasset-migrate, namespace: netasset }
spec:
  backoffLimit: 3
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: migrate
          image: registry.example.com/netasset/api:1.0
          command: ["alembic", "upgrade", "head"]
          envFrom:
            - configMapRef: { name: netasset-config }
            - secretRef: { name: netasset-secrets }
          env:
            - name: DATABASE_URL
              value: postgresql+asyncpg://netasset:$(DB_PASSWORD)@db:5432/netasset
```

```bash
kubectl apply -f migrate-job.yaml
kubectl -n netasset wait --for=condition=complete job/netasset-migrate --timeout=120s
```

## 4. API (Deployment + Service)

```yaml
apiVersion: v1
kind: Service
metadata: { name: api, namespace: netasset }
spec:
  selector: { app: api }
  ports: [{ port: 8000, targetPort: 8000 }]
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: api, namespace: netasset }
spec:
  replicas: 2
  selector: { matchLabels: { app: api } }
  template:
    metadata: { labels: { app: api } }
    spec:
      containers:
        - name: api
          image: registry.example.com/netasset/api:1.0
          ports: [{ containerPort: 8000 }]
          envFrom:
            - configMapRef: { name: netasset-config }
            - secretRef: { name: netasset-secrets }
          env:
            - name: DATABASE_URL
              value: postgresql+asyncpg://netasset:$(DB_PASSWORD)@db:5432/netasset
          readinessProbe:
            httpGet: { path: /health, port: 8000 }
            initialDelaySeconds: 15
            periodSeconds: 10
```

> Hinweis: `EMBEDDING_MODEL` (sentence-transformers) wird beim ersten Lauf
> geladen – für stabile Starts ggf. ins Image vorladen oder ein PVC als Cache
> mounten. CPU/RAM-Requests entsprechend setzen (Embeddings sind speicherhungrig).

## 5. Frontend (Deployment + Service)

```yaml
apiVersion: v1
kind: Service
metadata: { name: web, namespace: netasset }
spec:
  selector: { app: web }
  ports: [{ port: 80, targetPort: 80 }]
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: web, namespace: netasset }
spec:
  replicas: 2
  selector: { matchLabels: { app: web } }
  template:
    metadata: { labels: { app: web } }
    spec:
      containers:
        - name: web
          image: registry.example.com/netasset/web:1.0
          ports: [{ containerPort: 80 }]
```

## 6. Ingress (TLS via cert-manager)

Routing wie im Caddyfile: `/api`, `/auth`, `/health` → API, alles andere → Frontend.

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: netasset
  namespace: netasset
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  ingressClassName: nginx
  tls:
    - hosts: ["netasset.example.com"]
      secretName: netasset-tls
  rules:
    - host: netasset.example.com
      http:
        paths:
          - { path: /api,    pathType: Prefix, backend: { service: { name: api, port: { number: 8000 } } } }
          - { path: /auth,   pathType: Prefix, backend: { service: { name: api, port: { number: 8000 } } } }
          - { path: /health, pathType: Prefix, backend: { service: { name: api, port: { number: 8000 } } } }
          - { path: /,       pathType: Prefix, backend: { service: { name: web, port: { number: 80 } } } }
```

## Reihenfolge

```bash
kubectl apply -f 01-namespace-secret-config.yaml
kubectl apply -f 02-postgres.yaml
kubectl -n netasset rollout status statefulset/db
kubectl apply -f 03-migrate-job.yaml
kubectl -n netasset wait --for=condition=complete job/netasset-migrate --timeout=180s
kubectl apply -f 04-api.yaml -f 05-web.yaml -f 06-ingress.yaml
```

## Updates

```bash
docker build -t registry.example.com/netasset/api:1.1 . && docker push …
kubectl apply -f 03-migrate-job.yaml   # neue Migrationen
kubectl -n netasset set image deploy/api  api=registry.example.com/netasset/api:1.1
kubectl -n netasset set image deploy/web  web=registry.example.com/netasset/web:1.1
```

## Cron-Jobs (optional)

Tägliche Snapshots und CVE-Import als `CronJob` (gleiches API-Image):

```yaml
apiVersion: batch/v1
kind: CronJob
metadata: { name: daily-snapshots, namespace: netasset }
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: snapshots
              image: registry.example.com/netasset/api:1.0
              command: ["python", "scripts/daily_snapshots.py"]
              envFrom:
                - secretRef: { name: netasset-secrets }
              env:
                - name: DATABASE_URL
                  value: postgresql+asyncpg://netasset:$(DB_PASSWORD)@db:5432/netasset
```

(analog `scripts/import_cves.py --days 7`, `scripts/import_kev.py`).
