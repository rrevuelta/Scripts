if($args.count -ne 1) {
    Write-Host "Wrong input arguments!"
    exit
}

Write-Host "`n             ######    #########  #######    #  ##         #   #######                    #########       ###      #######    ######   ########  #######
            #      #       #      #      #   #  # #        #  #       #                   #        #     #   #     #      #  #      #  #         #      #
            #              #      #      #   #  #  #       #  #       #                   #        #    #     #    #      #  #         #         #      #      
             #             #      #      #   #  #   #      #  #                           #        #   #       #   #      #   #        #         #      #      
              #            #      #######    #  #    #     #  #                           #########   ##########   #######     #       #         #######
               #           #      ##         #  #     #    #  #            ############   #           #        #   ##           #      #####     ##
                #          #      # #        #  #      #   #  #  #####                    #           #        #   # #           #     #         # #
                 #         #      #  #       #  #       #  #  #       #                   #           #        #   #  #           #    #         #  #
                  #        #      #   #      #  #        # #  #       #                   #           #        #   #   #           #   #         #   #
             #     #       #      #    #     #  #         ##  #       #                   #           #        #   #    #     #     #  #         #    #
              #####        #      #     #    #  #          #   #######                    #           #        #   #     #     #####   ########  #     #`n" 

Write-Host "Searching useful strings... `n"

$path = $args
$strings = Get-Content -Path $path

[System.Collections.ArrayList]$ipv4_adresses = @()
[System.Collections.ArrayList]$ipv6_adresses = @()  
[System.Collections.ArrayList]$dll_names = @()
[System.Collections.ArrayList]$registry_keys = @()
[System.Collections.ArrayList]$urls = @()
[System.Collections.ArrayList]$process_names = @()


foreach ($string in $strings) {

    #IPv4
    if($string -match '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$') {

        [void]$ipv4_adresses.Add($string)

    #IPv6
    } elseif($string -match '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))') {
        
        [void]$ipv6_adresses.Add($string)

    #.dll files
    } elseif($string -match '^[a-zA-Z0-9]*.(dll|DLL)$') {
        
        [void]$dll_names.Add($string)

    #registry keys
    } elseif($string -match '^(HKEY_|HK)([a-zA-Z0-9\s_@\-\^!#.\:\/\$%&+={}\[\]\\*])+$') {

        [void]$registry_keys.Add($registry_keys)

    #URLs
    } elseif($string -match "([a-z]([a-z]|\d|\+|-|\.)*):(\/\/(((([a-z]|\d|-|\.|_|~|[\x00A0-\xD7FF\xF900-\xFDCF\xFDF0-\xFFEF])|(%[\da-f]{2})|[!\$&'\(\)\*\+,;=]|:)*@)?((\[(|(v[\da-f]{1,}\.(([a-z]|\d|-|\.|_|~)|[!\$&'\(\)\*\+,;=]|:)+))\])|((\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5]))|(([a-z]|\d|-|\.|_|~|[\x00A0-\xD7FF\xF900-\xFDCF\xFDF0-\xFFEF])|(%[\da-f]{2})|[!\$&'\(\)\*\+,;=])*)(:\d*)?)(\/(([a-z]|\d|-|\.|_|~|[\x00A0-\xD7FF\xF900-\xFDCF\xFDF0-\xFFEF])|(%[\da-f]{2})|[!\$&'\(\)\*\+,;=]|:|@)*)*|(\/((([a-z]|\d|-|\.|_|~|[\x00A0-\xD7FF\xF900-\xFDCF\xFDF0-\xFFEF])|(%[\da-f]{2})|[!\$&'\(\)\*\+,;=]|:|@)+(\/(([a-z]|\d|-|\.|_|~|[\x00A0-\xD7FF\xF900-\xFDCF\xFDF0-\xFFEF])|(%[\da-f]{2})|[!\$&'\(\)\*\+,;=]|:|@)*)*)?)|((([a-z]|\d|-|\.|_|~|[\x00A0-\xD7FF\xF900-\xFDCF\xFDF0-\xFFEF])|(%[\da-f]{2})|[!\$&'\(\)\*\+,;=]|:|@)+(\/(([a-z]|\d|-|\.|_|~|[\x00A0-\xD7FF\xF900-\xFDCF\xFDF0-\xFFEF])|(%[\da-f]{2})|[!\$&'\(\)\*\+,;=]|:|@)*)*)|((([a-z]|\d|-|\.|_|~|[\x00A0-\xD7FF\xF900-\xFDCF\xFDF0-\xFFEF])|(%[\da-f]{2})|[!\$&'\(\)\*\+,;=]|:|@)){0})(\?((([a-z]|\d|-|\.|_|~|[\x00A0-\xD7FF\xF900-\xFDCF\xFDF0-\xFFEF])|(%[\da-f]{2})|[!\$&'\(\)\*\+,;=]|:|@)|[\xE000-\xF8FF]|\/|\?)*)?(\#((([a-z]|\d|-|\.|_|~|[\x00A0-\xD7FF\xF900-\xFDCF\xFDF0-\xFFEF])|(%[\da-f]{2})|[!\$&'\(\)\*\+,;=]|:|@)|\/|\?)*)?") {

        [void]$urls.Add($string)

    } elseif($string -match '^[a-zA-Z0-9]*.(exe|EXE)$') {
        
        [void]$process_names.Add($string)

    }
}

#Show results
Write-Host "##########################################################################################"
Write-Host "# IPv4                                                                                   #"
Write-Host "##########################################################################################"
if($ipv4_adresses.Count -gt 0) {
    Write-Host "-"($ipv4_adresses -join "`n- ")
}
Write-Host "`n"
Write-Host "##########################################################################################"
Write-Host "# IPv6                                                                                   #"
Write-Host "##########################################################################################"
if($ipv6_adresses.Count -gt 0) {
    Write-Host "-"($ipv6_adresses -join "`n- ")
}
Write-Host "`n"
Write-Host "##########################################################################################"
Write-Host "# .DLL                                                                                   #"
Write-Host "##########################################################################################"
if($dll_names.Count -gt 0) {
    Write-Host "-"($dll_names -join "`n- ")
}
Write-Host "`n"
Write-Host "##########################################################################################"
Write-Host "# Registry Keys                                                                          #"
Write-Host "##########################################################################################"
if($registry_keys.Count -gt 0) {
    Write-Host "-"($registry_keys -join "`n- ")   
}
Write-Host "`n"
Write-Host "##########################################################################################"
Write-Host "# URLs                                                                                   #"
Write-Host "##########################################################################################"
if($urls.Count -gt 0) {
    Write-Host "-"($urls -join "`n- ")
}
Write-Host "`n"
Write-Host "##########################################################################################"
Write-Host "# .EXE                                                                                   #"
Write-Host "##########################################################################################"
if($urls.Count -gt 0) {
    Write-Host "-"($process_names -join "`n- ")
}
Write-Host "`n"