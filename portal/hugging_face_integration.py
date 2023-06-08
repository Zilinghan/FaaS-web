from huggingface_hub import HfApi, ModelFilter
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
    if (author):
        models = api.list_models(filter=model_filter, search=model_name, author=author)
    else:
        models = api.list_models(filter=model_filter, search=model_name)
    
    # Return list of model names
    return jsonify([model.modelId for model in models]), 200
