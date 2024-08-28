policy "aws_tags"{
    query = "data.terraform.analysis.deny"
    enforcement_level= "mandatory"
    description = "Ensure proper tags"

}