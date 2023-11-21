from flask import Flask, json, request, g
import logging, sys
import threading, time


logging.basicConfig(level=logging.DEBUG)
threadLock = threading.Lock()


# Opening JSON file
try:
  filename = sys.argv[1]
except FileNotFoundError:
  logging.error('Input file not found')
  sys.exit()

try:
  data_file= open(filename)
except OSError:
  logging.error('Could not open/read file: %s', filename)
  sys.exit()



# Returns JSON object
try:
  data = json.load(data_file)
except:
  logging.error('Could not load the json file: %s', filename)
  sys.exit()

# Close file
try:
  data_file.close()
except:
  logging.warn('failed to close the input file')


# Copying the vm's and the fw_rules to arrays
vms = data['vms']
fw_rules = data['fw_rules']

# Statistics in a JSON format:
stats = {'vm_count': len(vms), 'request_count': 0, 'avarage_request_time': 0}

app = Flask(__name__)


@app.route('/api/v1/attack', methods=['GET'])
def get_attack():
  vm_id = request.args.get('vm_id')
  try:
    attack_vector = get_attack_vector(vm_id)
  except Exception as e:
    return json.dumps(e.args), 412

  try:
    return json.dumps(attack_vector)
  except:
    logging.error('Could not dump the attack vector to JSON format')


@app.route('/api/v1/stats', methods=['GET'])
def get_stats():
  stats_vector = get_stats_vector()
  try:
    return json.dumps(stats_vector)
  except:
    logging.error('no stats vector')


@app.before_request
def before_request():
  g.start = time.time()

# Updates the statistics
@app.teardown_request
def teardown_request(exception=None):
    diff = time.time() - g.start
    with threadLock:
        total = stats['avarage_request_time'] * stats['request_count']
        stats['request_count'] += 1
        stats['avarage_request_time'] = (total + diff)/stats['request_count']

def get_stats_vector():
  with threadLock:
    return stats

# Returns JSON list of the virtual machine ids that can potentially attack the vm
def get_attack_vector(vm_id):
  if vm_id is None:
    logging.error('must have vm_id in the get_attack_vector')
    raise Exception('Error missing vm_id')
  logging.info('analyzing attack vector for %s' % vm_id)
  attack_vector = vms
  flag=0
  for vm in attack_vector:
    if vm['vm_id']==vm_id:
      flag= 1
  if flag==1:
      logging.info('The vm_id is in the cloud')
  else:
    logging.error('vm_id is NOT in the cloud')
    raise Exception('vm is not in the cloud')

  vm_ids = []
  my_tags_arr=[]
  for vm in vms:
    if vm['vm_id']== vm_id:
      my_tags_arr.append(vm['tags'])
  if not(my_tags_arr):
    logging.info('No tags in my machine- no one can attack me')
  for fw_rule in fw_rules:
    source_attack=fw_rule['source_tag']
    dest_attack=fw_rule['dest_tag']
    for tags in my_tags_arr:
      for m in tags:
        if m==dest_attack:
          logging.info('you need to worry, lets check..')
          for vm in attack_vector:
            for VMtags in vm['tags']:
              if VMtags==source_attack:
                vm_ids.append(vm['vm_id'])
  if not(vm_ids):
    logging.info('you are safe')
  else:
    #remove duplicates
    vm_ids = list(dict.fromkeys(vm_ids))
    logging.info('the vm that can attack on the screen')
  return vm_ids

if __name__ == '__main__':
       app.run(port=80)



