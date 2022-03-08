export interface ContextParameter {
    readonly projectName: string,
    readonly vpcId: string,
    readonly openSearchDomainName: string,
    readonly openSearchIndexName: string,
    readonly securityGroupIdsForOpenSearch: string[],
    readonly subnets: Subnet[],
    readonly bucketNameForFirehose: string,
    readonly securityGroupIdsForFirehose: string[]
}

export type Subnet = {
    subnetId: string,
    availabilityZone: string
};