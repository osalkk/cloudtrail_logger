#!/usr/bin/python

import boto3
import json
from boto3.s3.transfer import S3Transfer
import gzip


def poll_queue():
    print('Polling queue...')
    sqs = boto3.client('sqs')
    url = sqs.get_queue_url(QueueName='Cloudtrail-queue')['QueueUrl']
    messages = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10)
    if 'Messages' in messages:
        body = messages['Messages'][0]['Body']
        receipthandle = messages['Messages'][0]['ReceiptHandle']
        bucket = json.loads(body)['s3Bucket']
        object_key = json.loads(body)['s3ObjectKey'][0]

        parse_log(bucket, object_key)
        sqs.delete_message(QueueUrl=url, ReceiptHandle=receipthandle)
    else:
        print("There are no messages in the queue")


def parse_log(bucket, logfile):
    s3 = boto3.client('s3')
    transfer = S3Transfer(s3)
    local_file = '/tmp/cloudtrail'

    transfer.download_file(bucket, logfile, local_file)

    file = gzip.open(local_file, "r")
    file_content = json.loads(file.read().decode("utf-8"))['Records']
    for content in file_content:
        #print(content)
        if 'errorMessage' in content:
            if content['errorMessage'] == 'Failed authentication':
                print("Authentication failed username ", content['userIdentity']['userName'], "from the ip address ", content['sourceIPAddress'],)
    file.close()


if __name__ == "__main__":
    try:
        poll_queue()

    except:
        raise