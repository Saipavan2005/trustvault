"""File storage. S3 in production; a local folder for tests. Only the app role can touch the bucket."""
import json
import os

from flask import current_app


class S3Store:
    def __init__(self, cfg):
        import boto3
        self.c = boto3.client("s3", region_name=cfg["AWS_REGION"])
        self.docs, self.anchors = cfg["S3_BUCKET"], cfg["ANCHOR_BUCKET"]

    def put(self, key, data):
        self.c.put_object(Bucket=self.docs, Key=key, Body=data, ServerSideEncryption="AES256",
                          ContentType="application/octet-stream")

    def stream(self, key):
        return self.c.get_object(Bucket=self.docs, Key=key)["Body"].iter_chunks(65536)

    def put_anchor(self, key, obj):
        self.c.put_object(Bucket=self.anchors, Key=key, Body=json.dumps(obj).encode(),
                          ServerSideEncryption="AES256", ContentType="application/json")

    def get_anchor(self, key):
        try:
            return json.loads(self.c.get_object(Bucket=self.anchors, Key=key)["Body"].read())
        except Exception:
            return None


class LocalStore:
    def __init__(self, cfg):
        self.root = cfg["LOCAL_STORAGE_DIR"]
        os.makedirs(os.path.join(self.root, "docs"), exist_ok=True)
        os.makedirs(os.path.join(self.root, "anchors"), exist_ok=True)

    def _p(self, key):
        p = os.path.normpath(os.path.join(self.root, key))
        assert p.startswith(os.path.abspath(self.root)) or p.startswith(self.root)
        return p

    def put(self, key, data):
        with open(self._p(key), "wb") as f:
            f.write(data)

    def stream(self, key):
        with open(self._p(key), "rb") as f:
            yield f.read()

    def put_anchor(self, key, obj):
        with open(self._p(key), "w") as f:
            json.dump(obj, f)

    def get_anchor(self, key):
        try:
            with open(self._p(key)) as f:
                return json.load(f)
        except Exception:
            return None


def get_store():
    cfg = current_app.config
    return S3Store(cfg) if cfg["STORAGE_BACKEND"] == "s3" else LocalStore(cfg)
