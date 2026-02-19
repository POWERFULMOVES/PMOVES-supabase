# PMOVES.AI Integration Guide for Supabase

## Integration Complete

The PMOVES.AI integration template has been applied to Supabase.

## Next Steps

### 1. Customize Environment Variables

Edit the following files with your service-specific values:

- `env.shared` - Base environment configuration
- `env.tier-data` - DATA tier specific configuration
- `chit/secrets_manifest_v2.yaml` - Add your service's required secrets

### 2. Update Docker Compose

Add the PMOVES.AI environment anchor to your `docker-compose.yml`:

```yaml
services:
  supabase:
    <<: [*env-tier-data, *pmoves-healthcheck]
    # Your existing service configuration...
```

### 3. Integrate Health Check

Add the health check endpoint to your service:

```python
from pmoves_health import add_custom_check, get_health_status

@app.get("/healthz")
async def health_check():
    return await get_health_status()
```

### 4. Add Service Announcement

Add NATS service announcement to your startup:

```python
from pmoves_announcer import announce_service

@app.on_event("startup")
async def startup():
    await announce_service(
        slug="supabase",
        name="Supabase PostgreSQL + pgvector",
        url=f"http://supabase:3010",
        port=3010,
        tier="data"
    )
```

### 5. Test Integration

```bash
# Test health check
curl http://localhost:3010/healthz

# Verify environment variables loaded
docker compose exec supabase env | grep PMOVES
```

## Service Details

- **Name:** Supabase PostgreSQL + pgvector
- **Slug:** supabase
- **Tier:** data
- **Port:** 3010 (PostgREST)
- **Health Check:** http://localhost:3010/healthz
- **NATS Enabled:** False
- **GPU Enabled:** False

## Support

For questions or issues, see the PMOVES.AI documentation.
