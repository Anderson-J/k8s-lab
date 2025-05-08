# Laboratório prático de Kubernetes (K8s)

## Introdução

Esse repositório tem o objetivo de compilar meus aprendizados práticos de Kubernetes, sabendo disso, como uma forma de "licença poética" usarei muitas vezes linguagem informal e descontraída ao longo de minhas constatações, portanto não encare esse repositório como um estudo de caso acadêmico, o único objetivo é consolidar aprendizados enquanto me divirto um pouco com o K8s. Dito isso, espero que você que está olhando esse repositório sinta-se a vontade para me acompanhar em meus devaneios...

## Provisionando um cluster kubernetes do zero, pré-requisitos

Para iniciar esse laboratório começarei com uma VM linux com as seguintes especificações:

- SO: Ubuntu 24.04
- 4 VCPUS
- 8 GB RAM
- 100 GB HDD
- Rede 172.20.10.150/24 (Distribuída via DHCP na interface ens192)
- Provisionarei o IP estático 172.20.10.221/24 também na interface ens192

Como de praxe após pegar o SO zerado, iniciarei realizando update e upgrade padrão por motivos de segurança.

```shell
sudo apt update && sudo apt upgrade -y
```

Após isso como citado anteriormente iniciarei o provisionamento de um IP estático no endereço: 172.20.20.221 na interface ens192, essa decisão foi tomada pois se faz necessário um IP fixo para os nós de Control Plane do cluster e infelizmente eu não possuo gerencia a respeito do DHCP nesse laboratório, porém tenho conhecimento de um pool de IP que está disponível para provisionamento estático que posso utilizar, portanto, sabendo disso, esse é o motivo de provisionar esse ip na mesma interface de forma simplificada.

Inicio criando o arquivo `99-disable-network-config.cfg` com as configurações que preciso:

```shell
echo 'network: {config: disabled}' | sudo tee /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
```

Após isso edito o arquivo de configuração de rede `50-cloud-init.yaml` que já está provisionado de forma padrão no meu sistema:

```shell
sudo nano /etc/netplan/50-cloud-init.yaml
```

insiro o conteúdo abaixo de modo que eu mantenha o DHCP:

```yaml
network:
  ethernets:
    ens192:
      dhcp4: true # Manter DHCP
      addresses:
        - 172.20.10.221/24 # IP estático adicional
  version: 2
```

Após isso inicio dando uma lida na documentação oficial do kubernetes e percebo que um cluster kubernetes deve possuir alguns componentes essenciais ao nível de nó para seu devido funcionamento, são eles:

- [Container runtime](https://github.com/containerd/containerd/blob/main/docs/getting-started.md) (necessário para que os Pods consigam rodar dentro dos nós)
- [Kubelet](https://kubernetes.io/docs/concepts/architecture/#kubelet) (Um agente que roda em cada nó do cluster, ele garante que os containers estão rodando em um pod)

Além disso para a devida instalação de um cluster é necessário o cumprimento de alguns pré-requisitos, são eles:

- Habilitar o encaminhamento de pacotes IPV4
- Ter um Container runtime instalado e configurado
- Garantir que tanto o Kubelet e o Container Runtime utilizem o mesmo drive de [`cgourp`](https://kubernetes.io/docs/setup/production-environment/container-runtimes/#systemd-cgroup-driver) (O drive de `cgroup` impõe o controle de recursos de computação em um ambiente Linux e existem dois drivers de `cgroup` disponpíveis `cgroupfs` e `systemd`, além disso o uso de `cgroupfs` não é recomendado quando o `systemd` é o sistema de inicialização, pois o `systemd` espera um único gerenciador de `cgroups` no sistema. Além disso, se você usar o `cgroupv2` , use o `systemd` driver cgroup em vez de `cgroupfs`, no caso da nossa distribuição de Ubuntu o `cgroupv2` é o padrão do sistema.)

Para os pré-requisitos listados acima, começaremos habilitando o encaminhamento de pacotes IPV4 conforme abaixo:

```shell
cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.ipv4.ip_forward = 1
EOF
```

```shell
sudo sysctl --system
```

Para o pré-requisito seguinte, escolhi o `containerd` como Container Runtime, para garantir a instalação e configuração segui conforme os passos:

- Criei uma pasta para guardar os arquivos referentes ao `containerd`:

```shell
mkdir -p /root/containerd/components
```

- Baixei os recursos necessários

```shell
wget https://github.com/containerd/containerd/releases/download/v2.1.0/containerd-2.1.0-linux-amd64.tar.gz && wget https://github.com/opencontainers/runc/releases/download/v1.3.0/runc.amd64 && wget https://github.com/containernetworking/plugins/releases/download/v1.7.1/cni-plugins-linux-amd64-v1.7.1.tgz
```

- Instalei os recursos com os comandos

```shell
tar Cxzvf /usr/local containerd-2.1.0-linux-amd64.tar.gz && install -m 755 runc.amd64 /usr/local/sbin/runc && mkdir -p /opt/cni/bin && tar Cxzvf /opt/cni/bin cni-plugins-linux-amd64-v1.7.1.tgz
```

Também se faz necessário adicionar um serviço de controle ao `systemctl`, para isso precisaremos criar um arquivo `containerd.service` com o seguinte conteúdo:

> containerd.service

```service
# Copyright The containerd Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

[Unit]
Description=containerd container runtime
Documentation=https://containerd.io
After=network.target dbus.service

[Service]
ExecStartPre=-/sbin/modprobe overlay
ExecStart=/usr/local/bin/containerd

Type=notify
Delegate=yes
KillMode=process
Restart=always
RestartSec=5

# Having non-zero Limit*s causes performance problems due to accounting overhead
# in the kernel. We recommend using cgroups to do container-local accounting.
LimitNPROC=infinity
LimitCORE=infinity

# Comment TasksMax if your systemd version does not supports it.
# Only systemd 226 and above support this version.
TasksMax=infinity
OOMScoreAdjust=-999

[Install]
WantedBy=multi-user.target
```

para que seja reconhecido como um serviço pelo `systemctl` é necessário que esse arquivo esteja no local `/usr/local/lib/systemd/system/` e para isso garanti que a pasta foi criada com:

```shell
mkdir -p /usr/local/lib/systemd/system/
```

uma vez que tenha sido posicionado corretamente `/usr/local/lib/systemd/system/containerd.service` será necessário reiniciar os daemons:

```shell
systemctl daemon-reload
systemctl enable --now containerd
```

para confirmar que funcionou utilizei o comando:

```shell
systemctl status containerd # Expectativa de estar "enabled" + "running"
```

Já para o outro pré-requisito onde ue precisei descobrir qual é o sistema `cgroup` nativo da distribuição utilizei o comando abaixo:

```shell
stat -fc %T /sys/fs/cgroup/ # cgroup2fs
```

## Provisionando um cluster kubernetes do zero, o início da jornada

As principais formas de provisionamento de um cluster Kubernetes no momento que escrevo essa documentação são:

- kubeadm (Modo de instalação padrão)
- Cluster API: (Um subprojeto do Kubernetes focado em fornecer APIs declarativas e ferramentas para simplificar o provisionamento, a atualização e a operação de vários clusters do Kubernetes)
- kops: (Uma ferramenta automatizada de provisionamento de cluster)
- kubespray: Uma coleção de playbooks Ansible , inventários e ferramentas de provisionamento.

Apesar de a opção do `kops` parecer muito simplificada e atrativa, vou optar inicialmente pelo `kubeadm` no momento da escrita desse documento eu estou pensando em futuramente provisionar mais dois nós de control plane para testes de alta disponibilidade, acho que será interessante ver se há compatibilidade de provisionamento com recursos de bootstraping diferentes, bem... Não pretendo remover esse disclaimer, além de estar versionado com esse pensamento, então, se ver outras formas de provisionamento mais a frente saiba que minha curiosidade me venceu hehehe!

Continuando...

A versão do `kubeadm` que será instalada é a v1.33, e tem como requisitos necessários:

- Um host Linux compatível com Kernel LTS (A escolha óbvia geralmente é baseada em Debian ou Red Hat)
- 2 GB RAM ou superior
- 2 CPUs ou superior
- Conectividade de rede total entre todas as máquinas no cluster (Rede pública ou privada é suficiente)
- Hostname, endereço MAC e `product_uuid` exclusivos para cada nó
- Para distribuições que não sejam padrão Debian ou Red Hat é importante saber que é necessário garantir que haja um `glibc` ou uma camada de compatibilidade que forneça os símbolos esperados
- Desabilitar o swap ou criar tolerancia para o kubelet (O comportamento padrão de um kubelet é falhar ao iniciar se a memória swap for detectada em um nó. Isso significa que a swap deve ser desabilitada ou tolerada pelo kubelet)
- Intalar os pacotes kubeadm, kubelet e kubectl

### Portas

Algumas portas devem ter liberação para que não haja impacto no fornecimento do serviço

#### **Control Plane**

| Protocol  | Direction | Port Range  | Purpose                 | Used By               |
|-----------|-----------|-------------|-------------------------|-----------------------|
| TCP       | Inbound   | 6443        | Kubernetes API server   | All                   |
| TCP       | Inbound   | 2379-2380   | etcd server client API  | kube-apiserver, etcd  |
| TCP       | Inbound   | 10250       | Kubelet API             | Self, Control plane   |
| TCP       | Inbound   | 10259       | kube-scheduler          | Self                  |
| TCP       | Inbound   | 10257       | kube-controller-manager | Self                  |

Embora as portas etcd estejam incluídas na seção do Control Plane, você também pode hospedar seu próprio cluster `etcd` externamente ou em portas personalizadas.

#### **Worker Node**

| Protocol  | Direction | Port Range    | Purpose                 | Used By               |
|-----------|-----------|---------------|-------------------------|-----------------------|
| TCP       | Inbound   | 10250         | Kubelet API             | Self, Control plane   |
| TCP       | Inbound   | 10256         | kube-proxy              | Self, Load balancers  |
| TCP       | Inbound   | 30000-32767   | NodePort Services †     | All                   |

† Intervalo de portas padrão para NodePort Services .

## Continuando com os primeiros passos

Começarei instalando os pacotes kubeadm, kubelet e kubectl

```shell
sudo apt-get update && sudo apt-get install -y apt-transport-https ca-certificates curl gpg && sudo mkdir -p -m 755 /etc/apt/keyrings && curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.33/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg && echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.33/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list && sudo apt-get update && sudo apt-get install -y kubelet kubeadm kubectl && sudo systemctl enable --now kubelet
```

O processo de atualização de um cluster Kubernetes é um procedimento delicado e deve ser feito preferencialmente sob o domínio do administrador do cluster, por conta disso, utilizarei esse comando para marcar e travar a versão de instalação utilizada no momento da instalação dos pacotes kubeadm, kubelet e kubectl, posteriormente caso seja necessário, é possível modificar essa configuração para atualizações futuras.



```shell
sudo apt-mark hold kubelet kubeadm kubectl
```

Para organizar os arquivos referentes ao cluster criarei uma pasta chamada cluster que ficará no endereço `/root/cluster`

```shell
mkdir /root/cluster
```

Após uma leitura na documentação optei por iniciar o cluster com o `kubeadm` em duas partes, para a primeira iniciarei baixando as imagens necessárias para o provisionamento do Control Plane:

```shell
kubeadm config images pull
```

Também criarei um arquivo yaml com as primeiras especificações de configuração do kubeadm no caminho `/root/cluster/kubeadm`

```shell
mkdir -p /root/cluster/kubeadm && kubeadm config print init-defaults > kubeadm-config.yaml
```

O modelo do arquivo de configurações iniciais precisou ser modificado de acordo com meu ambiente e minhas necessidade e no final ficou ficou assim:

```yaml
apiVersion: kubeadm.k8s.io/v1beta4
kind: InitConfiguration
bootstrapTokens: 
- groups:
  - system:bootstrappers:kubeadm:default-node-token
  ttl: 24h0m0s
  usages:
  - signing
  - authentication
localAPIEndpoint:
  advertiseAddress: 172.20.10.221
  bindPort: 6443
nodeRegistration:
  criSocket: unix:///run/containerd/containerd.sock
  imagePullPolicy: IfNotPresent
  imagePullSerial: true
  name: US-KCP-01 
timeouts:
  controlPlaneComponentHealthCheck: 4m0s
  discovery: 5m0s
  etcdAPICall: 2m0s
  kubeletHealthCheck: 4m0s
  kubernetesAPICall: 1m0s
  tlsBootstrap: 5m0s
  upgradeManifests: 5m0s
---
apiVersion: kubeadm.k8s.io/v1beta4
kind: ClusterConfiguration
apiServer: {}
caCertificateValidityPeriod: 87600h0m0s
certificateValidityPeriod: 8760h0m0s
certificatesDir: /etc/kubernetes/pki
clusterName: US-KCP-01 
controllerManager: {}
dns: {}
encryptionAlgorithm: RSA-2048
etcd:
  local:
    dataDir: /var/lib/etcd
imageRepository: registry.k8s.io
kubernetesVersion: v1.33.0
networking:
  dnsDomain: lab.local
  serviceSubnet: 10.96.0.0/12
  podSubnet: 10.244.0.0/16
proxy: {}
scheduler: {}
kubeletConfiguration:
  apiVersion: kubelet.config.k8s.io/v1beta1
  kind: KubeletConfiguration
  cgroupDriver: systemd
```

Importante ressaltar que defini o `systemd` como driver `cgroup` no final do yaml, conforme especificado em etapa anterior com o comando `stat -fc %T /sys/fs/cgroup/` a saída desse comando foi `cgroup2fs`, portanto o recomendado nesse caso é que seja utilizado o `systemd` como driver de `cgroup`.

Após o download das imagens e com o arquivo `kubeadm-config.yaml` configurado, em teoria podemos, finalmente iniciar o provisionamento do cluster kubernetes

## Agora é a hora! Up and Running

Com tudo pronto e na pasta onde se encontra o arquivo `kube-config.yaml`, `/root/cluster/kubeadm`, utilizei o comando:

```shell
sudo kubeadm init --config kubeadm-config.yaml
```

Após isso, obtive sucesso ao provisionar o cluster, e comecei a seguir as instruções no output de sucesso:

```shell
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

Em caso de usuário root:

```shell
export KUBECONFIG=/etc/kubernetes/admin.conf
```

Como recomendação da saída, a próxima etapa será adicionar um addon para a comunicação de redes entre pods, mais a frente utilizarei o `calico`, mas antes disso, é importante saber que já existem pods rodando no cluster, inclusive pods que não estão funcionando devido a ausencia do addon de rede, utilizando o comando:

```shell
kubectl get pods -A
```

A saída esperada é a seguinte:

| NAMESPACE   | NAME                              | READY | STATUS  | RESTARTS  | AGE |
|-------------|-----------------------------------|-------|---------|-----------|-----|
| kube-system | coredns-674b8bbfcf-cg685          | 0/1   | Pending | 0         | 16m |
| kube-system | coredns-674b8bbfcf-wvfwm          | 0/1   | Pending | 0         | 16m |
| kube-system | etcd-us-kcp-01                    | 1/1   | Running | 0         | 16m |
| kube-system | kube-apiserver-us-kcp-01          | 1/1   | Running | 0         | 16m |
| kube-system | kube-controller-manager-us-kcp-01 | 1/1   | Running | 0         | 16m |
| kube-system | kube-proxy-snnhr                  | 1/1   | Running | 0         | 16m |
| kube-system | kube-scheduler-us-kcp-01          | 1/1   | Running | 0         | 16m |

## Começando os trabalhos...

Continuando com o que falamos antes, é necessário adicionar um addon de rede para a comunicação entre os pods, escolhemos o `calico` para desempenhar essa tarefa, portanto pretendo tratar da instalação do `calico`.




```txt

You should now deploy a pod network to the cluster.
Run "kubectl apply -f [podnetwork].yaml" with one of the options listed at:
  https://kubernetes.io/docs/concepts/cluster-administration/addons/

Then you can join any number of worker nodes by running the following on each as root:

kubeadm join 172.20.10.221:6443 --token x25yuq.x3e8jm84cqwkj11e \
        --discovery-token-ca-cert-hash sha256:b7017a6f87562a8cf6c10a775acf6ac4b36bc693282346b1b6a3e3ff9a59d1fa
```