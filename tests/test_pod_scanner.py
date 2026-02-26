import unittest
from src.core.finding import Finding
from src.modules.internal.pod_scanner import PodScanner
from kubernetes import client


class TestPodScanner(unittest.TestCase):
    
    def test_privileged_container_detection(self):
        scanner = PodScanner()
        
        pod = client.V1Pod(
            metadata=client.V1ObjectMeta(name="test-pod", namespace="default"),
            spec=client.V1PodSpec(
                containers=[
                    client.V1Container(
                        name="nginx",
                        image="nginx:latest",
                        security_context=client.V1SecurityContext(privileged=True)
                    )
                ]
            )
        )
        
        findings = scanner.scan([pod])
        
        privileged_findings = [f for f in findings if 'Privileged Container' in f.title]
        self.assertEqual(len(privileged_findings), 1)
        self.assertEqual(privileged_findings[0].severity, 'CRITICAL')
    
    def test_host_pid_detection(self):
        scanner = PodScanner()
        
        pod = client.V1Pod(
            metadata=client.V1ObjectMeta(name="test-pod", namespace="default"),
            spec=client.V1PodSpec(
                host_pid=True,
                containers=[
                    client.V1Container(name="nginx", image="nginx:latest")
                ]
            )
        )
        
        findings = scanner.scan([pod])
        
        host_pid_findings = [f for f in findings if 'hostPID' in f.title]
        self.assertEqual(len(host_pid_findings), 1)
        self.assertEqual(host_pid_findings[0].severity, 'HIGH')
    
    def test_docker_socket_mount(self):
        scanner = PodScanner()
        
        pod = client.V1Pod(
            metadata=client.V1ObjectMeta(name="test-pod", namespace="default"),
            spec=client.V1PodSpec(
                volumes=[
                    client.V1Volume(
                        name="docker-sock",
                        host_path=client.V1HostPathVolumeSource(path="/var/run/docker.sock")
                    )
                ],
                containers=[
                    client.V1Container(name="nginx", image="nginx:latest")
                ]
            )
        )
        
        findings = scanner.scan([pod])
        
        hostpath_findings = [f for f in findings if 'HostPath Mount' in f.title]
        self.assertEqual(len(hostpath_findings), 1)
        self.assertEqual(hostpath_findings[0].severity, 'CRITICAL')


if __name__ == '__main__':
    unittest.main()
