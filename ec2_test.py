import os
import sys


def deploy_instance():
    import boto3

    subnet_id = "subnet-d0eb14b6"
    vpc_id = 'vpc-6440e402'
    employee_name = 'N. Valkevich'
    availability_zone = 'eu-west-1c'

    ec2 = boto3.resource('ec2')
    client = boto3.client('ec2')

    print('Generating key')
    filepath = generate_key(client, ec2, employee_name)
    print('instance')
    instance = create_instance(ec2, employee_name, subnet_id)
    print('SG')
    create_security_group(client, ec2, instance, employee_name, vpc_id)
    print('volume')
    create_volume(ec2, instance, availability_zone)
    print('Bash')
    prepare_instance(instance, filepath)

    exit(0)


def generate_key(client, ec2, employee_name):
    dirpath = '.tmp/'
    filepath = dirpath + 'keypair.pem'

    client.delete_key_pair(KeyName=employee_name)
    key_pair = ec2.create_key_pair(KeyName=employee_name)

    os.system('mkdir -p ' + dirpath + ' && touch ' + filepath + ' && chmod 600 ' + filepath)
    f = open(filepath, 'w+')
    f.write(str(key_pair.key_material))
    f.close()

    return filepath


def create_instance(ec2, employee_name, subnet_id):
    instances = ec2.create_instances(
        # Ubuntu 16.04
        ImageId='ami-2a7d75c0',
        InstanceType='t2.micro',
        KeyName=employee_name,
        MinCount=1,
        MaxCount=1,
        NetworkInterfaces=[
            {
                'SubnetId': subnet_id,
                'DeviceIndex': 0,
                'AssociatePublicIpAddress': True
            }
        ]
    )
    instance = instances[0]
    ec2.create_tags(Resources=[instance.id], Tags=[{'Key': 'Name', 'Value': employee_name}])
    instance.wait_until_running()
    return instance


def create_security_group(client, ec2, instance, employee_name, vpc_id):
    security_group_id=0
    for group in client.describe_security_groups()['SecurityGroups']:
        if group['GroupName'] == employee_name:
            if employee_name == group['GroupName']:
                security_group_id = group['GroupId']
            instance.modify_attribute(Groups=[security_group_id])
    if not security_group_id:
        print('Creating security group...')
        security_group = ec2.create_security_group(GroupName=employee_name, Description="Test task", VpcId=vpc_id)
        print('Authorizing ingress...')
        security_group.authorize_ingress(
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [
                        {
                            'CidrIp': '0.0.0.0/0'
                        }
                    ]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [
                        {
                            'CidrIp': '0.0.0.0/0'
                        }
                    ]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'IpRanges': [
                        {
                            'CidrIp': '0.0.0.0/0'
                        }
                    ]
                }
            ]
        )
        instance.modify_attribute(Groups=[security_group.id])



def create_volume(ec2, instance, availability_zone):
    volume = ec2.create_volume(AvailabilityZone=availability_zone, Size=1, VolumeType='standard')
    os.system('sleep 5')
    volume.attach_to_instance(
        Device='/dev/xvdf',
        InstanceId=instance.id
    )


def prepare_instance(instance, filepath):
    import paramiko
    host = instance.public_ip_address
    user = 'ubuntu'

    commands = [
        'sudo /sbin/parted /dev/xvdf mklabel gpt --script',
        'sudo /sbin/parted /dev/xvdf mkpart primary 0% 100% --script',
        'sudo mkfs.ext4 /dev/xvdf1',
        'sudo apt update',
        'sudo apt install -y python3-pip git nginx',
        'pip3 install flask boto3',
        'sudo mkdir ~/website',
        'sudo mount /dev/xvdf1 ~/website',
        'cd ~/website',
	'sudo chown -R ubuntu ./',
        'git clone https://github.com/valkevichnv/ec2_test.git',	
	'sudo rm /etc/nginx/sites-available/default',
        'sudo rm /etc/nginx/sites-enabled/default',
        'echo -ne "server { \n\tlisten 80; \n\tlocation / { \n\t\tproxy_pass http://127.0.0.1:5000; \n\t} \n}" | sudo tee /etc/nginx/sites-enabled/default',
        'export FLASK_APP=~/website/ec2_test/ec2_test.py',
        'export FLASK_DEBUG=1',
	'echo "* * * * * cd /home/ubuntu/website/ec2_test && git pull" | sudo tee /var/spool/cron/crontabs/ubuntu',
	'sudo service nginx start',
        'flask run &' 
    ]

    auth_key = paramiko.RSAKey.from_private_key_file(filepath)
    conn = paramiko.SSHClient()
    conn.set_missing_host_key_policy(paramiko.AutoAddPolicy)
    conn.connect(hostname=host, username=user, pkey=auth_key)
    for cmd in commands:
        conn.exec_command(cmd)


def check_auth(username, password):
    return username == 'admin' and password == 'secret'


def authenticate():
    return Response(
        'Wrong credentials.\n', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})

flask_path = os.popen("which flask").read()[:-1]

print (flask_path + " | " +sys.argv[0])
if sys.argv[0] != flask_path:
    deploy_instance()

from functools import wraps
from flask import request, Response, Flask

app = Flask(__name__)
app.run(host='0.0.0.0', port=80, debug=True)


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)

    return decorated


@app.route('/')
@requires_auth
def secret_page():
    # get Mem and CPU usage

    usages = os.popen("ps axu | grep flask | grep Python | awk '{print $3, $4}'").read().split()
    cpu_usage = usages[0]
    mem_usage = usages[1]
    latest_commit = os.popen("git rev-parse --short HEAD").read()

    return 'Latest commit: ' + latest_commit + 'Mem usage: ' + str(mem_usage) + '% \n' + 'Cpu usage: ' + str(cpu_usage) + '% \n'
