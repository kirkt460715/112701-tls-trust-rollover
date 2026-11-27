"""TLS 信任轮换的持续审核：读取、核对并解释本地合成记录。"""

from .model import load_records
from .evaluate import evaluate

__all__ = ["load_records", "evaluate"]
