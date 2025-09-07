from netmiko import ConnectHandler

class DeviceConnection:
    def __init__(self, device_info: dict):
        self.device_info = device_info
        self.connection = None

    def connect(self):
        self.connection = ConnectHandler(**self.device_info)
        self.connection.enable()

    def execute(self, command):
      if isinstance(command, list):
            # Send multiple config commands in configuration mode
          output = self.connection.send_config_set(command)
      else:
            # Send a single operational (show) command
          output = self.connection.send_command(command)
      return output

    def save_configuration(self):
        return self.connection.send_command("write memory")

    def disconnect(self):
        if self.connection:
            self.connection.disconnect()
            self.connection = None