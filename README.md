*PSudo* is a powershell module that allows you to run a block of powershell code as another windows user.

To use PSudo, first import the module:

    Import-Module .\PSudo.psm1

Then use the following command:

    PSudo -domain <Domain> -username <UserName> -password <PassWord> -cmd { <Code> }
    
You can then remove the module if you like

    Remove-Module PSudo
    
Err.... that's it!