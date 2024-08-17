import random
import time

# Simulated environment
class Environment:
    def __init__(self):
        self.systems = {
            'Server1': {'status': 'healthy', 'data': 'important_data1'},
            'Server2': {'status': 'healthy', 'data': 'important_data2'},
            'Workstation1': {'status': 'healthy', 'data': 'personal_data1'},
            'Workstation2': {'status': 'healthy', 'data': 'personal_data2'}
        }
        self.incidents = []

    def simulate_attack(self, attack_type):
        affected_system = random.choice(list(self.systems.keys()))
        if attack_type == 'malware':
            self.systems[affected_system]['status'] = 'infected'
            self.incidents.append(f'Malware infection on {affected_system}')
        elif attack_type == 'data_breach':
            self.systems[affected_system]['status'] = 'compromised'
            self.incidents.append(f'Data breach on {affected_system}')
        elif attack_type == 'ransomware':
            self.systems[affected_system]['status'] = 'encrypted'
            self.incidents.append(f'Ransomware attack on {affected_system}')
        else:
            raise ValueError('Unknown attack type')
        print(f'Attack simulated: {attack_type} on {affected_system}')

    def display_status(self):
        print('\nCurrent System Status:')
        for system, info in self.systems.items():
            print(f'{system}: Status = {info["status"]}, Data = {info["data"]}')
        print('\n')

    def respond_to_incidents(self):
        print('Responding to incidents...')
        for incident in self.incidents:
            if 'malware' in incident:
                self.contain_and_eradicate(incident)
            elif 'data breach' in incident:
                self.contain_and_eradicate(incident)
            elif 'ransomware' in incident:
                self.contain_and_eradicate(incident)
            self.recover_from_incident(incident)
        self.incidents = []

    def contain_and_eradicate(self, incident):
        affected_system = incident.split(' ')[-1]
        print(f'Containing and eradicating {incident}...')
        time.sleep(2)  # Simulate time taken for response
        self.systems[affected_system]['status'] = 'healthy'
        print(f'{affected_system} is now healthy.')

    def recover_from_incident(self, incident):
        affected_system = incident.split(' ')[-1]
        print(f'Recovering from {incident}...')
        time.sleep(2)  # Simulate time taken for recovery
        print(f'{affected_system} has been recovered.')

def main():
    env = Environment()
    
    # Display initial system status
    env.display_status()

    # Simulate some attacks
    attacks = ['malware', 'data_breach', 'ransomware']
    for attack in attacks:
        env.simulate_attack(attack)

    # Display status after attacks
    env.display_status()

    # Respond to simulated incidents
    env.respond_to_incidents()

    # Display final status
    env.display_status()

if __name__ == '__main__':
    main()
