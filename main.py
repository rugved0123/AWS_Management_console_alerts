from datetime import datetime, timedelta, date
from boto3 import client
import gzip
import json
import requests
import boto3    
import botocore
import os 


slack_api_url = os.getenv('slack_api_url')
aws_access_key_id_value = os.getenv('aws_access_key_id_value')
aws_secret_access_key_value = os.getenv('aws_secret_access_key_value')
bucket_name = os.getenv('bucket_name')

s3_client = boto3.client('s3',
         aws_access_key_id=aws_access_key_id_value,
    aws_secret_access_key=aws_secret_access_key_value,
)
bucket = bucket_name

def downloadeventfiles3():
    BUCKET_NAME = 'cloudtraileventid' # replace with your bucket name where the event id will be stored to prevent duplication
    KEY = 'event.json' # replace with your object key

    s3 = boto3.resource('s3',aws_access_key_id=aws_access_key_id_value,
        aws_secret_access_key=aws_secret_access_key_value,)

    os.chdir('/tmp')
    dir_list = os.listdir()

    try:
        s3.Bucket(BUCKET_NAME).download_file(KEY, 'event.json')
        print('file copied')
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "404":
            print("The object does not exist.")


def get_aws_region():
    ec2 = boto3.client('ec2',region_name='ap-south-1',aws_access_key_id=aws_access_key_id_value,
    aws_secret_access_key=aws_secret_access_key_value, )
    regions = ec2.describe_regions().get('Regions',[] )
    return regions

def create_user_identity(result):
    user_dict = {}
    if 'userIdentity' in result:
        # print ("result",type(result))
        userIdentity = result['userIdentity']
        user_dict["*EventName*"] = str(result['eventName'])
        user_dict["*AwsRegion*"] = str(result['awsRegion'])
        user_dict["*EventSource*"] = 'Terraform' if result["userAgent"].__contains__("Terraform") or result["userAgent"].__contains__("aws-sdk-go") or result["userAgent"].__contains__("eks.amazonaws.com")  or result["userAgent"].__contains__("autoscaling.amazonaws.com")  or result["userAgent"].__contains__("ec2fleet.amazonaws.com") else result['userAgent'] 
       
        user_dict["*Usertype*"] = str(userIdentity['type']) if 'type' in userIdentity else ''
        user_dict['*UserName*'] = str(userIdentity['userName']) if 'userName' in userIdentity else 'Root'
        user_dict['*AWS_Account*'] = 'Rugved-PROD'
    return user_dict



def ec2_RunInstances(result,user_dict):
    if 'responseElements' in result:
        responseElements = result['responseElements']
        instancesSet = responseElements['instancesSet']
        items = items = instancesSet['items'] if 'items' in instancesSet else []
        for instances in range(len(items)):
            user_dict["*InstanceId*"] = str(items[instances]['instanceId'])
            instances = items[instances]
            # print('instances',instances)
            if 'tagSet' in instances:
                tags = instances['tagSet']
                # print('tags',tags)
                if 'items' in tags:
                    items = tags['items']
                    for x in range(len(items)):
                        data = items[x]
                        if 'value' in data:
                            instancename = data['value']
                            # print ('instancename',instancename)
                            user_dict["*instancename*"] = str(instancename)
            # print('user_dict',user_dict)
            message_Creation = messageCreation(user_dict)
    return user_dict

def ec2_CreateSecurityGroup(result,user_dict):
    if 'responseElements' in result:
        responseElements = result['responseElements']
        user_dict["*groupId*"] = str(responseElements['groupId']) if 'groupId' in responseElements else ''
        message_Creation = messageCreation(user_dict)
    return user_dict


def ec2_DeleteSecurityGroup(result,user_dict):
    if 'requestParameters' in result:
        requestParameters = result['requestParameters']
        user_dict["*groupId*"] = str(requestParameters['groupId']) if 'groupId' in requestParameters else requestParameters['groupName']
        message_Creation = messageCreation(user_dict)
    return user_dict

def ec2_AuthorizeSecurityGroupIngress(result, user_dict):
    if 'requestParameters' in result:
        requestParameters = result['requestParameters']
        user_dict["groupId"] = str(requestParameters['groupId']) if 'groupId' in requestParameters else requestParameters['groupName']
        ipPermissions = requestParameters['ipPermissions'] if 'ipPermissions' in requestParameters else {}
        items =ipPermissions['items'] if 'items' in ipPermissions else []
        for ports in range(len(items)):
            user_dict["*ipProtocol*"] = str(items[ports]['ipProtocol'])
            user_dict["*portAdded*"] = str(items[ports]['fromPort'])
            ipRanges = (items[ports]['ipRanges'])
            items = ipRanges['items'] if 'items' in ipRanges else []
            for cidrIp in range(len(items)):
                user_dict["*cidrIp*"] = str(items[cidrIp]['cidrIp'])
                message_Creation = messageCreation(user_dict)
    return user_dict

def ec2_AuthorizeSecurityGroupEgress(result, user_dict):
    if 'requestParameters' in result:
        requestParameters = result['requestParameters']
        user_dict["*groupId*"] = str(requestParameters['groupId']) if 'groupId' in requestParameters else requestParameters['groupName']
        ipPermissions = requestParameters['ipPermissions'] if 'ipPermissions' in requestParameters else {}
        items = ipPermissions['items'] if 'items' in ipPermissions else []
        for ports in range(len(items)):
            user_dict["*ipProtocol*"] = str(items[ports]['ipProtocol'])
            user_dict["*portAdded*"] = str(items[ports]['fromPort'])
            ipRanges = (items[ports]['ipRanges'])
            items = ipRanges['items'] if 'items' in ipRanges else []
            for cidrIp in range(len(items)):
                user_dict["*cidrIp*"] = str(items[cidrIp]['cidrIp'])
                message_Creation = messageCreation(user_dict)
    return user_dict

def ec2_CreateVolume(result, user_dict):
    if 'responseElements' in result:
        responseElements = result['responseElements']
        volume_key = ["volumeId", "size", "volumeType"]
        for key in range(len(volume_key)):
            if responseElements:
                print('found')
                if volume_key[key] in responseElements:
                    user_dict[volume_key[key]] = str(responseElements[volume_key[key]])
                else:
                    print('not found')
            else:
                    print('found null')

    message_Creation = messageCreation(user_dict)
    return user_dict

def ec2_DeleteVolume(result, user_dict):
    if 'requestParameters' in result:
        requestParameters = result['requestParameters']
        user_dict["*volumeId*"] = str(requestParameters['volumeId']) if requestParameters else ''
        message_Creation = messageCreation(user_dict)
    return user_dict

def ec2_ModifyVolume(result, user_dict):
    if 'responseElements' in result:
        responseElements = result['responseElements']
        if 'ModifyVolumeResponse' in responseElements:
            ModifyVolumeResponse = responseElements['ModifyVolumeResponse']
            if 'volumeModification' in ModifyVolumeResponse:
                volumeModification = ModifyVolumeResponse['volumeModification']
                volume_key = ["volumeId", "originalSize", "targetSize", "originalVolumeType", "targetVolumeType"]
                for key in range(len(volume_key)):
                    if volume_key[key] in volumeModification:
                        user_dict[volume_key[key]] = str(volumeModification[volume_key[key]])
                        message_Creation = messageCreation(user_dict)
    return user_dict
            
def ec2_CreateUser(result, user_dict):
    if 'responseElements' in result:
        responseElements = result['responseElements']
        if 'user' in responseElements:
            user = responseElements['user']
            user_dict["*userName*"] = str(user['userName'])
            user_dict["*userId*"] = str(user['userId'])
            message_Creation = messageCreation(user_dict)
    return user_dict
    
def ec2_DeleteUser(result, user_dict):
    if 'requestParameters' in result:
        requestParameters = result['requestParameters']
        user_dict["*userDeleted*"] = str(requestParameters['userName'])
        message_Creation = messageCreation(user_dict)
    return user_dict

def get_cloudtrail_events_from_s3():
    dt = datetime.now() 
    day = str ("0%s" % (dt.day)) if dt.day<=9 else str(dt.day)
    month = str ("0%s" % (dt.month)) if dt.month<=9 else str(dt.month)
    regions_list = get_aws_region()
    for region in regions_list:
        # Prefix can be found from s3 bucket where the events are been stored 
        Prefix = 'AWSLogs/201895223380/CloudTrail/'+ region["RegionName"] +'/'+ str (dt.year) +'/'+ str (month)  +'/'+str (day) +'/'
        response = s3_client.list_objects_v2(Bucket=bucket, Prefix=Prefix)
        all = response['Contents'] if 'Contents' in response else []
        latest = max(all, key=lambda x: x['LastModified']) if all else {}
        if 'Key' not in latest:
            continue
        paginator = s3_client.get_paginator("list_objects_v2")
        if latest:
            for page in paginator.paginate(Bucket=bucket, Prefix=latest['Key']):
                for list_result in page["Contents"]:
                    s3_key = list_result["Key"]
                    if not s3_key.endswith(".json.gz"):
                        continue
                    s3_obj = s3_client.get_object(Bucket=bucket, Key=s3_key)
                    with gzip.open(s3_obj["Body"]) as infile:
                        records = json.load(infile)           
                        Get_Cloudtrail_IAM_events_from_s3 = get_cloudtrail_IAM_events_from_s3()
                        fetching_Events = fetching_events(records)
                        # ec2_Run_Instances = ec2_RunInstances(records)

def get_cloudtrail_IAM_events_from_s3():
    dt = datetime.now() 
    day = str ("0%s" % (dt.day)) if dt.day<=9 else str(dt.day)
    month = str ("0%s" % (dt.month)) if dt.month<=9 else str(dt.month)
    regions_list = get_aws_region()
    for region in regions_list:
        Prefix = 'AWSLogs/201895223380/CloudTrail/'+region["RegionName"]+'/'+ str ("0%s" % (dt.year)) +'/'+ str (month) +'/'+ str (day) +'/'
        response = s3_client.list_objects_v2(Bucket=bucket, Prefix=Prefix)
        all = response['Contents']   if 'Contents' in response else []    
        latest = max(all, key=lambda x: x['LastModified']) if all else {}
        if 'Key' not in latest:
            continue
        paginator = s3_client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix=latest['Key']):
            for list_result in page["Contents"]:
                s3_key = list_result["Key"]
                if not s3_key.endswith(".json.gz"):
                    continue
                s3_obj = s3_client.get_object(Bucket=bucket, Key=s3_key)
                with gzip.open(s3_obj["Body"]) as infile:
                    records02 = json.load(infile)
                    
                    fetching_Events = fetching_IAM_events(records02)

def readFile():
    os.chdir('/tmp')
    dir_list = os.listdir() 
    with open('/tmp/event.json','r') as fp:
            data = json.load(fp)
            # print("data is", data)
            eventIdlist = data["eventIdlist"] if 'eventIdlist' in data else []
    return eventIdlist

def writeFile(eventIdlist):
    os.chdir('/tmp')
    information= {}
    with open('/tmp/event.json', 'w') as fp:
        information["eventIdlist"] = eventIdlist
        # print("information", information)
        json.dump(information, fp, indent=2)

def uploadeventfile_S3():
    # print('uploadeventfile_S3',uploadeventfile_S3)
    BUCKET_NAME = 'cloudtraileventid' # replace with your bucket name
    KEY = 'event.json' # replace with your object key

    s3_client = boto3.client('s3',
            aws_access_key_id=aws_access_key_id_value,
        aws_secret_access_key=aws_secret_access_key_value,
    )
    os.chdir('/tmp')
    
    dir_list = os.listdir()
    s3_client.upload_file(
        Filename="/tmp/event.json",
        Bucket=BUCKET_NAME,
        Key=KEY,
    )
    # print('dir_list2',dir_list)
    print ('file uploaded successfully')



def fetching_events(records):
    downloadeventfiles3()
    if 'Records' in records:
        records = records['Records']
        eventIdlist = readFile()
        testList = []
        for x in range(len(records)):
            result = records[x]
            eventName = result['eventName']
            eventId = result['eventID']
            if eventId in eventIdlist:
                print("eventId found in eveentlist")
                continue 
            eventIdlist.append(eventId)
            
            data = []
            user_dict = create_user_identity(result)
            user_dict["*EventId*"] =  str(result["eventID"])
            testList.append(user_dict)
            if user_dict['*EventSource*'] == 'Terraform':
                continue
            
            # print("user_dict",user_dict)
            
            if (eventName == 'RunInstances' or eventName == 'TerminateInstances' or eventName == 'StopInstances' or eventName == 'StartInstances'):
                 ec2_Run_Instances = ec2_RunInstances(result, user_dict)
                 data.append(ec2_Run_Instances)
            elif (eventName == 'CreateSecurityGroup'):
                 ec2_CreateSecurity_Group = ec2_CreateSecurityGroup(result, user_dict)
                 data.append(ec2_CreateSecurity_Group)
            elif (eventName == 'DeleteSecurityGroup'):
                 ec2_DeleteSecurity_Group = ec2_DeleteSecurityGroup(result,user_dict)
                 data.append(ec2_DeleteSecurity_Group)
            elif (eventName == 'AuthorizeSecurityGroupIngress'):
                 ec2_Authorize_SecurityGroupIngress = ec2_AuthorizeSecurityGroupIngress(result,user_dict)
                 data.append(ec2_Authorize_SecurityGroupIngress)
            elif (eventName == 'AuthorizeSecurityGroupEgress'):
                 ec2_AuthorizeSecurityGroup_Egress = ec2_AuthorizeSecurityGroupEgress(result, user_dict)
                 data.append(ec2_AuthorizeSecurityGroup_Egress)
            elif (eventName == 'CreateVolume'):
                 ec2_Create_Volume = ec2_CreateVolume(result, user_dict)
                 data.append(ec2_Create_Volume)
            elif (eventName == 'DeleteVolume'):
                 ec2_Delete_Volume = ec2_DeleteVolume(result, user_dict)
                 data.append(ec2_Delete_Volume)
            elif (eventName == 'ModifyVolume'):
                 ec2_Modify_Volume = ec2_ModifyVolume(result, user_dict)
                 data.append(ec2_Modify_Volume)
        writeFile(eventIdlist)
        upload_eventfile_S3= uploadeventfile_S3()
        
            
def fetching_IAM_events(records02):
    if 'Records' in records02:
        records02 = records02['Records']
        eventIdlist = readFile()
        for x in range(len(records02)):
            result = records02[x]
            eventName = result['eventName']
            eventId = result['eventID']
            if eventId in eventIdlist:
                print("eventId found in eveentlist")
                continue 
            eventIdlist.append(eventId)
            
            data = []
            user_dict = create_user_identity(result)
            if (eventName == 'CreateUser'):
                ec2_Create_User = ec2_CreateUser(result, user_dict)
                data.append(ec2_Create_User)
            elif (eventName == 'DeleteUser'):
                 ec2_Delete_User = ec2_DeleteUser(result, user_dict)
                 data.append(ec2_Delete_User)
        writeFile(eventIdlist)

def messageCreation(result):
        str = ',\n '.join( key + ": " + value for key, value in result.items())
        message = {
            "type": "home",
            "blocks": [
                {
                    "type": "divider"
                },
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "AWS_ALERT"
                    }
                },
                {
                    "type": "divider"
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": str
                        }

                    ]
                }
            ]
        }
        sendSlack_Notification = sendSlackNotification(message)

def sendSlackNotification(message):
    api_url = slack_api_url
    todo = message
    headers =  {"Content-Type":"application/json"}
    response = requests.post(api_url, data=json.dumps(todo),headers=headers)
    # print("response",response.status_code)


def lambda_handler(event, context): 
    get_cloudtrail_events_from_s3()
    print("We did it ! from Lambda!")
    return {
        'statusCode': 200,
        'body': json.dumps('We did it ! from Lambda!')
    }

start = lambda_handler('test','test')