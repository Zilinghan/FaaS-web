from huggingface_hub import HfApi, ModelFilter, HfFileSystem
from flask import Blueprint, request, jsonify

hf_bp = Blueprint('hugging_face_integration', __name__)

@hf_bp.route('/models', methods=['GET'])
def get_models():
    model_name = request.args.get('model_name')
    task = request.args.get('task')
    library = request.args.get('library')
    dataset = request.args.get('dataset')
    author = request.args.get('author')

    model_filter_args = {}
    if task: model_filter_args['task'] = task
    if library: model_filter_args['library'] = library
    if dataset: model_filter_args['trained_dataset'] = dataset

    model_filter = ModelFilter(**model_filter_args)

    api = HfApi()
    number_limit = 30 # the limit number of models returned
    if (author):
        models = api.list_models(filter=model_filter, search=model_name, author=author, limit=number_limit)
    else:
        models = api.list_models(filter=model_filter, search=model_name, limit=number_limit)
    
    # Return list of model names
    return jsonify([model.modelId for model in models]), 200

@hf_bp.route('/models/<model_name>/', defaults={'path': ''})
@hf_bp.route('/models/<model_name>/<path:path>', defaults={'path': ''})
def get_files(path):
    fs = HfFileSystem()
    return jsonify(fs.ls(path, detail=False)), 200