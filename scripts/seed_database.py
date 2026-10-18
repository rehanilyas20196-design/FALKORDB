import sys
import os

# Add root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.app.db.falkordb import db_manager
from backend.config import settings

def seed():
    print(f"Connecting to FalkorDB at {settings.FALKORDB_HOST}:{settings.FALKORDB_PORT}...")
    db_manager.connect()
    graph = db_manager.get_graph()
    
    print("Clearing existing demo graph data...")
    try:
        graph.query("MATCH (n) DETACH DELETE n")
    except Exception as e:
        print(f"Note on clear: {e}")

    print("Seeding synthetic security graph entities...")
    
    # Create Users
    graph.query("CREATE (:User {id: 'usr_01', name: 'Alice Smith', email: 'alice@company.com', role: 'Engineer'})")
    graph.query("CREATE (:User {id: 'usr_02', name: 'Bob Jones', email: 'bob@company.com', role: 'Finance Analyst'})")
    
    # Create Devices
    graph.query("CREATE (:Device {id: 'dev_01', name: 'Alice MacBook Pro', os: 'macOS', trusted: true})")
    graph.query("CREATE (:Device {id: 'dev_02', name: 'Unknown Windows PC', os: 'Windows 10', trusted: false})")
    
    # Create IPs
    graph.query("CREATE (:IP {address: '192.168.1.50', country: 'United States', risk_score: 0.1})")
    graph.query("CREATE (:IP {address: '203.0.113.42', country: 'Unknown Proxy', risk_score: 0.85})")
    
    # Create Events & Relationships
    graph.query("""
        MATCH (u:User {id: 'usr_01'}), (d:Device {id: 'dev_01'}), (ip:IP {address: '192.168.1.50'})
        CREATE (e:Event {id: 'evt_101', timestamp: '2026-10-18T10:00:00Z', type: 'LOGIN_SUCCESS', description: 'Successful login from trusted device'})
        CREATE (u)-[:USED_DEVICE]->(d)
        CREATE (d)-[:CONNECTED_FROM]->(ip)
        CREATE (e)-[:ASSOCIATED_WITH]->(u)
        CREATE (e)-[:ASSOCIATED_WITH]->(d)
        CREATE (e)-[:ASSOCIATED_WITH]->(ip)
    """)

    graph.query("""
        MATCH (u:User {id: 'usr_01'}), (d:Device {id: 'dev_02'}), (ip:IP {address: '203.0.113.42'})
        CREATE (e:Event {id: 'evt_102', timestamp: '2026-10-18T11:15:00Z', type: 'UNFAMILIAR_DEVICE_LOGIN', description: 'Login attempt from unknown device and high-risk IP'})
        CREATE (a:Alert {id: 'alt_001', severity: 'HIGH', title: 'Unfamiliar Device & Suspicious IP Login', status: 'OPEN', timestamp: '2026-10-18T11:15:05Z'})
        CREATE (u)-[:USED_DEVICE]->(d)
        CREATE (d)-[:CONNECTED_FROM]->(ip)
        CREATE (e)-[:ASSOCIATED_WITH]->(u)
        CREATE (e)-[:ASSOCIATED_WITH]->(d)
        CREATE (e)-[:ASSOCIATED_WITH]->(ip)
        CREATE (a)-[:INVESTIGATES]->(e)
    """)

    print("Graph successfully seeded with initial security events and alerts!")

if __name__ == "__main__":
    seed()