// Rule will be triggered if text string is present 

rule Rule5
{
    strings:
        $text_string = "xX_not_a_virus_Xx"

    condition:
       $text_string
}
