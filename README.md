# Laboratório prático de Kubernetes (K8s)

## Introdução

Esse repositório tem o objetivo de compilar meus aprendizados práticos de Kubernetes, sabendo disso, como uma forma de "licença poética" usarei muitas vezes linguagem informal e descontraída ao longo de minhas constatações, portanto não encare esse repositório como um estudo de caso acadêmico, o único objetivo é consolidar aprendizados enquanto me divirto um pouco com o K8s. Dito isso, espero que você que está olhando esse repositório sinta-se a vontade para me acompanhar em meus devaneios...

## Provisionando um cluster kubernetes do zero, o início da jornada

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



Para descobrir qual é o sistema `cgroup` nativo da sua distribuição utilize o comando:
```shell
stat -fc %T /sys/fs/cgroup/
```



Para definir systemdcomo driver cgroup, edite a KubeletConfiguration opção de cgroupDrivere defina-a como systemd conforme exemplo:

```yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
...
cgroupDriver: systemd
```