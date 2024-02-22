import { EC2Client, DescribeInstancesCommand, DescribeSecurityGroupsCommand } from "@aws-sdk/client-ec2";

const auditRegions = ["us-east-1", "us-east-2", "us-west-2"];
const sensitivePorts = [22 /* SSH */, 80 /* HTTP */, 443 /* HTTPS */];

// Fetch instances from a region
const getInstancesInRegion = async (ec2Client) => {
    try {
        const { Reservations } = await ec2Client.send(new DescribeInstancesCommand({}));
        return Reservations.flatMap(reservation => reservation.Instances);
    } catch (error) {
        console.error('Error fetching instances:', error);
        return [];
    }
};

// Fetch security group information
const getSecurityGroupDetails = async (ec2Client, securityGroupIds) => {
    try {
        const { SecurityGroups } = await ec2Client.send(new DescribeSecurityGroupsCommand({ GroupIds: securityGroupIds }));
        return SecurityGroups;
    } catch (error) {
        console.error('Error fetching security group details:', error);
        return [];
    }
};

// Auditing for a region
const auditRegion = async (region) => {
    console.log(`Auditing instances in ${region}...`);
    const ec2Client = new EC2Client({ region });
    const instances = await getInstancesInRegion(ec2Client);

    for (const instance of instances) {
        const securityGroupIds = instance.SecurityGroups.map(sg => sg.GroupId);
        const securityGroups = await getSecurityGroupDetails(ec2Client, securityGroupIds);

        const exposed = securityGroups.some(sg => sg.IpPermissions.some(perm => 
            perm.FromPort && perm.ToPort && sensitivePorts.some(port => port >= perm.FromPort && port <= perm.ToPort)
        ));

        console.log(`Instance ${instance.InstanceId} in ${region} is ${exposed ? 'exposed' : 'secure'}.`);
    }
};

// Execute audits across all regions
const auditInstancesForExposedPorts = async () => {
    await Promise.all(auditRegions.map(auditRegion));
};

auditInstancesForExposedPorts().catch(console.error);
