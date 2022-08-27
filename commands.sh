#!/bin/bash -eux

function deploy () {
  # WARN: .gitkeep is also added to /.gitkeep
  for src in `find /home/isucon/webapp/all -type f`; do
    dst="$(echo $src | sed "s/\/home\/isucon\/webapp\/all//")"
    sudo cp $src $dst
  done
  for src in `find /home/isucon/webapp/$HOSTNAME -type f`; do
    dst=$(echo $src | sed "s/\/home\/isucon\/webapp\/$HOSTNAME//")
    sudo cp $src $dst
  done

  # build
  (cd /home/isucon/webapp/go && go build -o app)

  sudo systemctl daemon-reload
  # sudo systemctl restart nginx
  # sudo systemctl restart mysql
  # sudo systemctl restart isucon.go

  sudo sysctl -p /etc/sysctl.d/99-isucon.conf
}

function sync () {
  if [[ $# -ne 1 ]] ; then
    echo "requires one argument (branch_name)."
    return
  fi

  git fetch && \
  git reset --hard origin/$1 # <branch_name>
  source /home/isucon/webapp/commands.sh
}

function gather () {
  for file in `cat /home/isucon/webapp/target.txt`; do
    mkdir -p /home/isucon/webapp/all$(dirname $file)
    sudo cp $file /home/isucon/webapp/all$file
  done
}
