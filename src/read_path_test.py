import pickle

log_path = "./logs/evaluator.pkl"
with open(log_path, "rb") as f:
    all_paths = pickle.load(f)

# Duyệt qua danh sách các đường tấn công
for path in all_paths:
    print(path)
