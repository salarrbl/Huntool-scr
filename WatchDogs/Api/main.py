#!/usr/bin/env python3

import asyncio
import logging
import os
import re
import sys
from contextlib import asynccontextmanager
from datetime import datetime
from typing import List, Optional

import motor.motor_asyncio
from fastapi import Depends, FastAPI, Header, HTTPException  # Import Header
from pydantic import BaseModel, Field

# --- Configuration from Environment Variables ---
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017/watchdogs")
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", 8080))
API_KEY = os.getenv(
    "WATCHDOGS_API_KEY", ""
)  # Read the key from environment variable set by server.go

# --- Logging ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

sys.dont_write_bytecode = True


# --- Dependency for API Key Authentication ---
async def verify_api_key(
    x_api_key: str = Header(..., alias="X-API-Key")
):  # Define dependency
    if not API_KEY or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return x_api_key  # Optionally return the key if needed later


# --- Async Context Manager for Startup/Shutdown ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Connecting to MongoDB: {MONGODB_URI}")
    app.mongodb_client = motor.motor_asyncio.AsyncIOMotorClient(MONGODB_URI)
    app.db = app.mongodb_client.watchdogs
    try:
        logger.info("Connected to MongoDB (using motor directly for queries)")
        yield
    except Exception as e:
        logger.error(f"Error connecting to DB or during startup: {e}")
        raise
    finally:
        app.mongodb_client.close()
        logger.info("Closed MongoDB connection")


# --- FastAPI App Instance ---
app = FastAPI(
    title="Watchdogs API",
    description="RESTful API for the Watchdogs security automation tool.",
    version="1.0.0",
    lifespan=lifespan,
)


def get_db():
    return app.db


# --- Helper Functions ---
async def get_target_config(db, target_name: str) -> Optional[TargetConfigOut]:
    collection = db.get_collection("targets")
    target_doc = await collection.find_one({"domain": target_name.lower()})
    if target_doc:
        return TargetConfigOut(**target_doc)
    return None


# --- API Routes ---
# Apply the dependency globally using middleware or by adding it to each route.
# Adding it to each route explicitly is safer and clearer for this use case.
# Example for the root route:
@app.get("/", dependencies=[Depends(verify_api_key)])  # Add dependency here
async def root():
    return {"message": "Welcome to the Watchdogs API! Check /docs for endpoints."}


# Health check
@app.get("/health", dependencies=[Depends(verify_api_key)])
async def health_check(db=Depends(get_db)):
    try:
        await db.command("ping")
        return {"status": "healthy", "timestamp": datetime.utcnow()}
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=500, detail="Database connection failed")


# Targets
@app.get("/targets", response_model=List[str], dependencies=[Depends(verify_api_key)])
async def list_targets(db=Depends(get_db)):
    try:
        collection = db.get_collection("targets")
        cursor = collection.find({}, {"domain": 1, "_id": 0})
        target_docs = await cursor.to_list(length=None)
        domains = [doc["domain"] for doc in target_docs if "domain" in doc]
        return domains
    except Exception as e:
        logger.error(f"Error listing targets: {e}")
        raise HTTPException(status_code=500, detail="Failed to list targets")


# All other routes need the dependency added too:
@app.get(
    "/breads/http/distinct",
    response_model=List[str],
    dependencies=[Depends(verify_api_key)],
)
async def get_all_distinct_http_subdomains(db=Depends(get_db)):
    try:
        collection = db.get_collection("http")
        distinct_values = await collection.distinct("subdomain")
        return [val for val in distinct_values if val]
    except Exception as e:
        logger.error(f"Error fetching distinct HTTP subdomains: {e}")
        raise HTTPException(
            status_code=500, detail="Failed to fetch distinct HTTP subdomains"
        )


@app.get(
    "/breads/subs/distinct",
    response_model=List[str],
    dependencies=[Depends(verify_api_key)],
)
async def get_all_distinct_subdomain_subdomains(db=Depends(get_db)):
    try:
        collection = db.get_collection("subdomains")
        distinct_values = await collection.distinct("subdomain")
        return [val for val in distinct_values if val]
    except Exception as e:
        logger.error(f"Error fetching distinct subdomain subdomains: {e}")
        raise HTTPException(
            status_code=500, detail="Failed to fetch distinct subdomain subdomains"
        )


@app.get(
    "/breads/http/ports",
    response_model=List[str],
    dependencies=[Depends(verify_api_key)],
)
async def get_all_subdomains_with_open_ports(db=Depends(get_db)):
    try:
        collection = db.get_collection("http")
        cursor = collection.find(
            {"ports.0": {"$exists": True}}, {"subdomain": 1, "_id": 0}
        )
        docs = await cursor.to_list(length=None)
        subdomains = [doc["subdomain"] for doc in docs if "subdomain" in doc]
        return list(set(subdomains))
    except Exception as e:
        logger.error(f"Error fetching subdomains with open ports: {e}")
        raise HTTPException(
            status_code=500, detail="Failed to fetch subdomains with open ports"
        )


@app.get(
    "/breads/{target_name}/http",
    response_model=List[str],
    dependencies=[Depends(verify_api_key)],
)
async def get_http_subdomains(target_name: str, db=Depends(get_db)):
    try:
        collection = db.get_collection("http")
        cursor = collection.find(
            {"root_domain": target_name.lower()}, {"subdomain": 1, "_id": 0}
        )
        docs = await cursor.to_list(length=None)
        subdomains = [doc["subdomain"] for doc in docs if "subdomain" in doc]
        return subdomains
    except Exception as e:
        logger.error(f"Error fetching HTTP subdomains for {target_name}: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to fetch HTTP subdomains for {target_name}"
        )


@app.get(
    "/breads/{target_name}/http/all",
    response_model=List[dict],
    dependencies=[Depends(verify_api_key)],
)
async def get_http_all_details(target_name: str, db=Depends(get_db)):
    try:
        collection = db.get_collection("http")
        cursor = collection.find({"root_domain": target_name.lower()}, {"_id": 0})
        docs = await cursor.to_list(length=None)
        results = []
        for doc in docs:
            result_entry = {
                "subdomain": doc.get("subdomain", ""),
                "title": doc.get("title", ""),
                "status_code": doc.get("status_code", 0),
                "ports": doc.get("ports", []),
                "technologies": doc.get("technologies", []),
            }
            results.append(result_entry)
        return results
    except Exception as e:
        logger.error(f"Error fetching HTTP details for {target_name}: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to fetch HTTP details for {target_name}"
        )


@app.get(
    "/breads/{target_name}/http/title",
    response_model=List[dict],
    dependencies=[Depends(verify_api_key)],
)
async def get_http_titles(target_name: str, db=Depends(get_db)):
    try:
        collection = db.get_collection("http")
        cursor = collection.find(
            {"root_domain": target_name.lower()},
            {"subdomain": 1, "title": 1, "_id": 0},
        )
        docs = await cursor.to_list(length=None)
        results = []
        for doc in docs:
            subdomain = doc.get("subdomain", "")
            title = doc.get("title", "")
            if subdomain and title:
                results.append({"subdomain": subdomain, "title": title})
        return results
    except Exception as e:
        logger.error(f"Error fetching HTTP titles for {target_name}: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to fetch HTTP titles for {target_name}"
        )


@app.get(
    "/breads/{target_name}/http/status-code",
    response_model=List[dict],
    dependencies=[Depends(verify_api_key)],
)
async def get_http_status_codes(target_name: str, db=Depends(get_db)):
    try:
        collection = db.get_collection("http")
        cursor = collection.find(
            {"root_domain": target_name.lower()},
            {"subdomain": 1, "status_code": 1, "_id": 0},
        )
        docs = await cursor.to_list(length=None)
        results = []
        for doc in docs:
            subdomain = doc.get("subdomain", "")
            status_code = doc.get("status_code", 0)
            if subdomain:
                results.append({"subdomain": subdomain, "status_code": status_code})
        return results
    except Exception as e:
        logger.error(f"Error fetching HTTP status codes for {target_name}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch HTTP status codes for {target_name}",
        )


@app.get(
    "/breads/{target_name}/http/ports",
    response_model=List[dict],
    dependencies=[Depends(verify_api_key)],
)
async def get_http_ports(target_name: str, db=Depends(get_db)):
    try:
        collection = db.get_collection("http")
        cursor = collection.find(
            {"root_domain": target_name.lower(), "ports.0": {"$exists": True}},
            {"subdomain": 1, "ports": 1, "_id": 0},
        )
        docs = await cursor.to_list(length=None)
        results = []
        for doc in docs:
            subdomain = doc.get("subdomain", "")
            ports = doc.get("ports", [])
            if subdomain and ports:
                results.append({"subdomain": subdomain, "ports": ports})
        return results
    except Exception as e:
        logger.error(f"Error fetching HTTP ports for {target_name}: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to fetch HTTP ports for {target_name}"
        )


@app.get(
    "/breads/{target_name}/http/cdn",
    response_model=List[dict],
    dependencies=[Depends(verify_api_key)],
)
async def get_http_cdn(target_name: str, db=Depends(get_db)):
    try:
        collection = db.get_collection("http")
        cursor = collection.find(
            {"root_domain": target_name.lower()},
            {"subdomain": 1, "cdn": 1, "_id": 0},
        )
        docs = await cursor.to_list(length=None)
        results = []
        for doc in docs:
            subdomain = doc.get("subdomain", "")
            cdn = doc.get("cdn", "")
            if subdomain and cdn:
                results.append({"subdomain": subdomain, "cdn": cdn})
        return results
    except Exception as e:
        logger.error(f"Error fetching HTTP CDN for {target_name}: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to fetch HTTP CDN for {target_name}"
        )


@app.get(
    "/breads/{target_name}/http/content-length",
    response_model=List[dict],
    dependencies=[Depends(verify_api_key)],
)
async def get_http_content_length(target_name: str, db=Depends(get_db)):
    try:
        collection = db.get_collection("http")
        cursor = collection.find(
            {"root_domain": target_name.lower()},
            {"subdomain": 1, "content_length": 1, "_id": 0},
        )
        docs = await cursor.to_list(length=None)
        results = []
        for doc in docs:
            subdomain = doc.get("subdomain", "")
            content_length = doc.get("content_length", 0)
            if subdomain and content_length and content_length > 0:
                results.append(
                    {"subdomain": subdomain, "content_length": content_length}
                )
        return results
    except Exception as e:
        logger.error(f"Error fetching HTTP content length for {target_name}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch HTTP content length for {target_name}",
        )


@app.get(
    "/breads/{target_name}/http/tech",
    response_model=List[dict],
    dependencies=[Depends(verify_api_key)],
)
async def get_http_tech(target_name: str, db=Depends(get_db)):
    try:
        collection = db.get_collection("http")
        cursor = collection.find(
            {"root_domain": target_name.lower()},
            {"subdomain": 1, "technologies": 1, "_id": 0},
        )
        docs = await cursor.to_list(length=None)
        results = []
        for doc in docs:
            subdomain = doc.get("subdomain", "")
            technologies = doc.get("technologies", [])
            if subdomain and technologies and len(technologies) > 0:
                results.append({"subdomain": subdomain, "technologies": technologies})
        return results
    except Exception as e:
        logger.error(f"Error fetching HTTP technologies for {target_name}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch HTTP technologies for {target_name}",
        )


@app.get(
    "/breads/{target_name}/http/cve",
    response_model=List[dict],
    dependencies=[Depends(verify_api_key)],
)
async def get_nuclei_findings(target_name: str, db=Depends(get_db)):
    try:
        collection = db.get_collection("http")
        cursor = collection.find(
            {
                "root_domain": target_name.lower(),
                "nuclei_findings.0": {"$exists": True},
            },
            {"subdomain": 1, "nuclei_findings": 1, "_id": 0},
        )
        docs = await cursor.to_list(length=None)
        results = []
        for doc in docs:
            for finding in doc.get("nuclei_findings", []):
                results.append(
                    {
                        "subdomain": doc.get("subdomain", ""),
                        "template_id": finding.get("template_id"),
                        "name": finding.get("name"),
                        "severity": finding.get("severity"),
                        "url": finding.get("url"),
                        "type": finding.get("type"),
                        "host": finding.get("host"),
                    }
                )
        return results
    except Exception as e:
        logger.error(f"Error fetching Nuclei findings for {target_name}: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to fetch Nuclei findings for {target_name}"
        )


@app.get(
    "/breads/{target_name}/subs/target",
    response_model=List[str],
    dependencies=[Depends(verify_api_key)],
)
async def get_subdomain_records(target_name: str, db=Depends(get_db)):
    try:
        target_collection = db.get_collection("targets")
        target_doc = await target_collection.find_one({"domain": target_name.lower()})
        if not target_doc:
            logger.warning(
                f"Target '{target_name}' not found in 'targets' collection. Querying 'subdomains' with root_domain='{target_name.lower()}'."
            )
            collection = db.get_collection("subdomains")
            cursor = collection.find(
                {"root_domain": target_name.lower()}, {"subdomain": 1, "_id": 0}
            )
            docs = await cursor.to_list(length=None)
            subdomains = [doc["subdomain"] for doc in docs if "subdomain" in doc]
            return list(set(subdomains))

        in_scope_patterns = target_doc.get("in_scope", [])
        logger.info(
            f"Found target '{target_name}' with in_scope patterns: {in_scope_patterns}"
        )
        root_domains_to_query = [target_name.lower()] + [
            p.lower() for p in in_scope_patterns
        ]

        collection = db.get_collection("subdomains")
        query = {"root_domain": {"$in": root_domains_to_query}}
        cursor = collection.find(query, {"subdomain": 1, "_id": 0})
        docs = await cursor.to_list(length=None)
        subdomains = [doc["subdomain"] for doc in docs if "subdomain" in doc]
        return list(set(subdomains))
    except Exception as e:
        logger.error(f"Error fetching subdomain records for {target_name}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch subdomain records for {target_name}",
        )


@app.get(
    "/breads/{target_name}/vh-hosts",
    response_model=List[str],
    dependencies=[Depends(verify_api_key)],
)
async def get_virtual_hosts(target_name: str, db=Depends(get_db)):
    try:
        collection = db.get_collection("virtual_host")
        cursor = collection.find(
            {"root_domain": target_name.lower()}, {"subdomain": 1, "_id": 0}
        )
        docs = await cursor.to_list(length=None)
        subdomains = [doc["subdomain"] for doc in docs if "subdomain" in doc]
        return subdomains
    except Exception as e:
        logger.error(f"Error fetching virtual hosts for {target_name}: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to fetch virtual hosts for {target_name}"
        )


@app.get(
    "/hot-breads", response_model=List[str], dependencies=[Depends(verify_api_key)]
)
async def get_hot_breads_subdomains(db=Depends(get_db)):
    try:
        collection = db.get_collection("hot-breads")
        cursor = collection.find({}, {"subdomain": 1, "_id": 0})
        docs = await cursor.to_list(length=None)
        subdomains = [doc["subdomain"] for doc in docs if "subdomain" in doc]
        return subdomains
    except Exception as e:
        logger.error(f"Error fetching hot-breads subdomains: {e}")
        raise HTTPException(
            status_code=500, detail="Failed to fetch hot-breads subdomains"
        )


@app.get("/providers", response_model=List[str], dependencies=[Depends(verify_api_key)])
async def list_available_providers(db=Depends(get_db)):
    try:
        collection = db.get_collection("subdomains")
        distinct_providers = await collection.distinct("providers")
        all_providers = set()
        for provider_list in distinct_providers:
            if isinstance(provider_list, list):
                all_providers.update(provider_list)
            elif isinstance(provider_list, str):
                all_providers.add(provider_list)
        return sorted(list(all_providers))
    except Exception as e:
        logger.error(f"Error listing providers: {e}")
        raise HTTPException(status_code=500, detail="Failed to list providers")


@app.get(
    "/breads/{target_name}/subs/provider/{provider_name}",
    response_model=List[str],
    dependencies=[Depends(verify_api_key)],
)
async def get_subdomains_by_provider_for_target(
    target_name: str, provider_name: str, db=Depends(get_db)
):
    try:
        target_collection = db.get_collection("targets")
        target_doc = await target_collection.find_one({"domain": target_name.lower()})
        if not target_doc:
            logger.warning(
                f"Target '{target_name}' not found in 'targets' collection. Querying 'subdomains' with root_domain='{target_name.lower()}'."
            )
            collection = db.get_collection("subdomains")
            query = {
                "root_domain": target_name.lower(),
                "providers": {
                    "$size": 1,
                    "$elemMatch": {
                        "$regex": f"^{re.escape(provider_name)}$",
                        "$options": "i",
                    },
                },
            }
            cursor = collection.find(query, {"subdomain": 1, "_id": 0})
            docs = await cursor.to_list(length=None)
            subdomains = [doc["subdomain"] for doc in docs if "subdomain" in doc]
            return subdomains

        in_scope_patterns = target_doc.get("in_scope", [])
        logger.info(
            f"Found target '{target_name}' with in_scope patterns for provider filter: {in_scope_patterns}"
        )
        root_domains_to_query = [target_name.lower()] + [
            p.lower() for p in in_scope_patterns
        ]

        collection = db.get_collection("subdomains")
        query = {
            "root_domain": {"$in": root_domains_to_query},
            "providers": {
                "$size": 1,
                "$elemMatch": {
                    "$regex": f"^{re.escape(provider_name)}$",
                    "$options": "i",
                },
            },
        }
        cursor = collection.find(query, {"subdomain": 1, "_id": 0})
        docs = await cursor.to_list(length=None)
        subdomains = [doc["subdomain"] for doc in docs if "subdomain" in doc]
        return subdomains
    except Exception as e:
        logger.error(
            f"Error fetching subdomains for target '{target_name}' and provider '{provider_name}': {e}"
        )
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch subdomains for target '{target_name}' and provider '{provider_name}'",
        )
