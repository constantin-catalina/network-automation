#!/bin/bash
# ==============================
# Day 1 Linux Setup
# ==============================

# Creare directoare pentru departamente
mkdir -p /inginerie
mkdir -p /vanzari
mkdir -p /is

# Creare grupuri
groupadd inginerie
groupadd vanzari
groupadd is

# Creare admini
useradd -m -d /home/admin_inginerie -s /bin/bash -g inginerie admin_inginerie
useradd -m -d /home/admin_vanzari -s /bin/bash -g vanzari admin_vanzari
useradd -m -d /home/admin_is -s /bin/bash -g is admin_is

# Permisiuni directoare
chown admin_inginerie:inginerie /inginerie
chown admin_vanzari:vanzari /vanzari
chown admin_is:is /is

chmod 775 /inginerie
chmod 775 /vanzari
chmod 775 /is

# Creare utilizatori simpli
useradd -m -d /home/ing1 -s /bin/bash -g inginerie ing1
useradd -m -d /home/ing2 -s /bin/bash -g inginerie ing2

useradd -m -d /home/sales1 -s /bin/bash -g vanzari sales1
useradd -m -d /home/sales2 -s /bin/bash -g vanzari sales2

useradd -m -d /home/is1 -s /bin/bash -g is is1
useradd -m -d /home/is2 -s /bin/bash -g is is2

# Setare parole implicite
echo "admin_inginerie:parola123" | chpasswd
echo "ing1:parola123" | chpasswd
echo "ing2:parola123" | chpasswd

echo "admin_vanzari:parola123" | chpasswd
echo "sales1:parola123" | chpasswd
echo "sales2:parola123" | chpasswd

echo "admin_is:parola123" | chpasswd
echo "is1:parola123" | chpasswd
echo "is2:parola123" | chpasswd

echo "[INFO] Configurare Day 1 finalizată!"
