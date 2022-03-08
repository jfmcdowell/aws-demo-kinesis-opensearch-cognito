import base64
import gzip
import io
import json
import logging
import os
import time

logger = logging.getLogger(__name__)
logger.setLevel(os.getenv('LOG_LEVEL', 'DEBUG'))
formatter = logging.Formatter("%(asctime)s %(created)f %(name)s:%(lineno)s [%(levelname)s] %(funcName)s : %(message)s")
for handler in logger.handlers:
    handler.setFormatter(formatter)

def transform(data):
    # TODO: transform record

    return data

def process_record(record):
    record_id = record['recordId']
    logger.info(f"Record ID: {record_id}")
    logger.debug('Raw data:')
    logger.debug(record)

    data = decode_record(record['data'])
    logger.debug('Decoded data:')
    logger.debug(data)

    data = transform(data)
    logger.debug('Transformed data')
    logger.debug(data)

    data = encode_data(record_id, data)
    logger.debug('Encoded data')
    logger.debug(data)

    return data

def decode_record(encoded_data):
    data = base64.b64decode(encoded_data)
    data = data.decode('utf-8')
    return data

def encode_data(record_id, data):
    data = data.encode('utf-8')
    record = {
        'data': base64.b64encode(data).decode('utf-8'),
        'result': 'Ok',
        'recordId': record_id
    }
    return record

def lambda_handler(event, context):
    logger.debug(event)
    records = [process_record(r) for r in event['records']]
    return {'records': records }
