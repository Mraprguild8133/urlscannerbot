class Database:
    def is_connected(self):
        try:
            # Simple ping or query
            self.client.admin.command('ping')
            return True
        except:
            return False
          
