    
package terraform.analysis

import input as tfplan

########################
# Parameters for Policy
########################
resource_types := ["aws_s3_bucket"]
mandatory_tags := ["environment", "project", "owner"]

#########
# Functions
#########
array_contains(arr, elem) {
    arr[_] = elem
}

missing_tags(resource_tags, required_tags) := missing {
    existing_tags := {tag | resource_tags[tag]}
    required_set := {tag | tag := required_tags[_]}
    missing := required_set - existing_tags
}

#########
# Policy
#########
deny[msg] {
    res := tfplan.resource_changes[_]
    res.type == resource_types[_]
    res.change.actions[_] != "delete"
    
    resource_tags := object.get(res.change.after, "tags", {})
    missing := missing_tags(resource_tags, mandatory_tags)
    count(missing) > 0
    
    msg := sprintf("Resource '%v' of type '%v' is missing mandatory tags: %v", [res.name, res.type, concat(", ", missing)])
}
