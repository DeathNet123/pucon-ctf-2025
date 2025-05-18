## Basic BOF Kernel

# How to Run (Local)
1. Launch the virtual machine by `./startvm`
2. Inside the VM, login as user `scada` without password
3. Copy your exploit to the VM by using the copy2vm script `./copy2vm <path-to-your-exploit>`
4. Run the exploit inside the VM by `./<your-exploit>`

# How to Run (Remote)
1. Launch and connect to your instance by using ssh `ssh -i img/bookworm.id_rsa -p 1337 scada@<instance-ip>`
2. Copy your exploit to the VM by using scp `scp -i img/bookworm.id_rsa -P 1337 <path-to-your-exploit> scada@<instance-ip>:~/`
3. Run the exploit inside the VM by `./<your-exploit>`
