import json, pickle, sys
sys.path.insert(0, '/Users/nguyenvantoan/dev/PYTHON_PROJECTS/APK/ml')
import importlib
import feature_extractor as fe
importlib.reload(fe)

meta  = json.loads(open('/Users/nguyenvantoan/dev/PYTHON_PROJECTS/APK/ml/model_meta.json').read())
model = pickle.load(open('/Users/nguyenvantoan/dev/PYTHON_PROJECTS/APK/ml/model.pkl','rb'))

# Test 1: simulate real DEX string pool (class descriptors + method name strings)
real_fast = {
    'permissions': {
        'requested': ['android.permission.SEND_SMS', 'android.permission.READ_PHONE_STATE'],
        'declared': []
    },
    'api_calls': [],  # fast mode: no external calls here
    'components': {'activities': [], 'services': [], 'receivers': [], 'providers': []},
    'strings': [
        'Ljava/lang/Runtime;',
        'Ldalvik/system/DexClassLoader;',
        'Landroid/telephony/TelephonyManager;',
        'Ljavax/crypto/Cipher;',
        'Ljava/lang/ProcessBuilder;',
        'exec',
        'getDeviceId',
        'getSubscriberId',
        'loadClass',
        'getRuntime',
        '/system/bin/su',
        'android.intent.action.BOOT_COMPLETED',
    ],
    'network': {'urls': [], 'domains': [], 'ips': []},
}

vec  = fe.extract_features(real_fast, meta['feature_cols'])
prob = model.predict_proba([vec])[0]
pred = model.predict([vec])[0]
matched = [meta['feature_cols'][i] for i, v in enumerate(vec) if v == 1]
print('=== Real fast-mode malware ===')
print('Features matched:', len(matched))
print('Matched:', matched)
print('Prediction:', meta['classes'][pred], '| Malware prob:', round(prob[meta['malware_index']]*100, 1), '%')

# Test 2: benign app (fast mode)
benign = {
    'permissions': {'requested': ['android.permission.INTERNET', 'android.permission.VIBRATE'], 'declared': []},
    'api_calls': [],
    'components': {'activities': [], 'services': [], 'receivers': [], 'providers': []},
    'strings': [
        'Landroid/app/Activity;',
        'Landroid/content/Intent;',
        'Ljava/net/HttpURLConnection;',
        'onCreate',
        'onResume',
        'connect',
        'Hello World',
    ],
    'network': {'urls': ['https://example.com'], 'domains': ['example.com'], 'ips': []},
}
vec2  = fe.extract_features(benign, meta['feature_cols'])
prob2 = model.predict_proba([vec2])[0]
pred2 = model.predict([vec2])[0]
matched2 = [meta['feature_cols'][i] for i, v in enumerate(vec2) if v == 1]
print()
print('=== Real fast-mode benign ===')
print('Features matched:', len(matched2))
print('Matched:', matched2)
print('Prediction:', meta['classes'][pred2], '| Malware prob:', round(prob2[meta['malware_index']]*100, 1), '%')


meta  = json.loads(open('/Users/nguyenvantoan/dev/PYTHON_PROJECTS/APK/ml/model_meta.json').read())
model = pickle.load(open('/Users/nguyenvantoan/dev/PYTHON_PROJECTS/APK/ml/model.pkl','rb'))

# Simulate MALWARE APK in fast mode:
# - permissions from manifest
# - api_calls: ONLY app-defined methods (fast mode limitation)
# - BUT strings include DEX class descriptors for all REFERENCED classes
fake_malware = {
    'permissions': {
        'requested': ['android.permission.SEND_SMS','android.permission.READ_SMS','android.permission.RECEIVE_BOOT_COMPLETED','android.permission.READ_PHONE_STATE'],
        'declared': []
    },
    'api_calls': [
        # Only app-defined methods - as returned by fast mode
        {'class': 'Lcom/evil/malware/Main;', 'name': 'onCreate', 'descriptor': '()V', 'signature': 'Lcom/evil/malware/Main;->onCreate()V'},
    ],
    'components': {
        'activities': [], 'services': [],
        'receivers': [{'name': 'BootReceiver', 'intent_filters': {'actions': ['android.intent.action.BOOT_COMPLETED'], 'categories': [], 'data': []}, 'exported': True, 'permission': None}],
        'providers': []
    },
    # Fast-mode: DEX string pool includes referenced class descriptors
    'strings': [
        'Ldalvik/system/DexClassLoader;',           # DexClassLoader feature
        'Ljava/lang/Runtime;',                       # Runtime feature
        'Landroid/telephony/TelephonyManager;',      # TelephonyManager
        'Ljavax/crypto/Cipher;',                     # Cipher
        '/system/bin/su',                            # /system/bin feature
        'android.intent.action.BOOT_COMPLETED',
    ],
    'network': {'urls': [], 'domains': [], 'ips': []},
}

vec  = extract_features(fake_malware, meta['feature_cols'])
prob = model.predict_proba([vec])[0]
pred = model.predict([vec])[0]
print('=== MALWARE simulation ===')
print('Features non-zero:', sum(vec))
print('Prediction:', meta['classes'][pred], '| Malware prob:', round(prob[meta['malware_index']]*100, 1), '%')

# Show which features matched
matched = [meta['feature_cols'][i] for i,v in enumerate(vec) if v == 1]
print('Matched features:', matched[:20])

print()

# Simulate BENIGN APK (fast mode)
fake_benign = {
    'permissions': {'requested': ['android.permission.INTERNET', 'android.permission.VIBRATE', 'android.permission.ACCESS_NETWORK_STATE'], 'declared': []},
    'api_calls': [
        {'class': 'Lcom/example/app/MainActivity;', 'name': 'onCreate', 'descriptor': '()V', 'signature': 'Lcom/example/app/MainActivity;->onCreate()V'},
    ],
    'components': {'activities': [{'name': 'MainActivity', 'intent_filters': {'actions': [], 'categories': [], 'data': []}, 'exported': False, 'permission': None}], 'services': [], 'receivers': [], 'providers': []},
    'strings': [
        'Landroid/content/Intent;',
        'Landroid/app/Activity;',
        'Hello World',
        'Ljava/net/HttpURLConnection;',
    ],
    'network': {'urls': ['https://example.com'], 'domains': ['example.com'], 'ips': []},
}
vec2  = extract_features(fake_benign, meta['feature_cols'])
prob2 = model.predict_proba([vec2])[0]
pred2 = model.predict([vec2])[0]
print('=== BENIGN simulation ===')
print('Features non-zero:', sum(vec2))
print('Prediction:', meta['classes'][pred2], '| Malware prob:', round(prob2[meta['malware_index']]*100, 1), '%')
matched2 = [meta['feature_cols'][i] for i,v in enumerate(vec2) if v == 1]
print('Matched features:', matched2[:20])

