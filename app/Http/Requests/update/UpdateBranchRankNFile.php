<?php

namespace App\Http\Requests\update;

use Illuminate\Foundation\Http\FormRequest;

class UpdateBranchRankNFile extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return array_merge(
            $this->mainRules(),
            $this->jobKnowledgeRules(),
            $this->qualityOfWorkRules(),
            $this->adaptabilityRules(),
            $this->teamworkRules(),
            $this->reliabilityRules(),
            $this->ethicalRules(),
            $this->customerServiceRules(),
        );
    }
public function mainRules()
    {
        return [
            'rating'                                => ['required', 'numeric'],
            'performance_score'                     => ['required', 'numeric'],
            'coverage_from'                         => ['required', 'date'],
            'coverage_to'                           => ['required', 'date'],
            'reviewTypeProbationary'                => ['nullable', 'numeric'],
            'reviewTypeRegular'                     => ['nullable', 'string'],
            'reviewTypeOthersImprovement'           => ['nullable', 'boolean'],
            'reviewTypeOthersCustom'                => ['nullable', 'string'],
            'priority_area_1'                       => ['required', 'string', 'min:20'],
            'priority_area_2'                       => ['nullable', 'string', 'min:20'],
            'priority_area_3'                       => ['nullable', 'string', 'min:20'],
            'remarks'                               => ['nullable', 'string'],
        ];
    }

     public function jobKnowledgeRules()
    {
        return [
            'job_knowledge'                             => ['required', 'array'],
            'job_knowledge.*.id'                        => ['required', 'numeric'],
            'job_knowledge.*.score'                     => ['required', 'numeric'],
            'job_knowledge.*.comment'                   => ['required', 'string'],
        ];
    }

    public function qualityOfWorkRules()
    {
        return [
            'quality_of_works'                             => ['required', 'array'],
            'quality_of_works.*.id'                        => ['required', 'numeric'],
            'quality_of_works.*.score'                     => ['nullable', 'numeric'],
            'quality_of_works.*.comment'                   => ['nullable', 'string'],
        ];
    }

    public function adaptabilityRules()
    {
        return [
            'adaptabilities'                             => ['required', 'array'],
            'adaptabilities.*.id'                        => ['required', 'numeric'],
            'adaptabilities.*.score'                     => ['required', 'numeric'],
            'adaptabilities.*.comment'                   => ['required', 'string'],
        ];
    }

    public function teamworkRules()
    {
        return [
            'teamworks'                             => ['required', 'array'],
            'teamworks.*.id'                        => ['required', 'numeric'],
            'teamworks.*.score'                     => ['required', 'numeric'],
            'teamworks.*.comment'                   => ['required', 'string'],
        ];
    }

    public function reliabilityRules()
    {
        return [
            'reliabilities'                             => ['required', 'array'],
            'reliabilities.*.id'                        => ['required', 'numeric'],
            'reliabilities.*.score'                     => ['required', 'numeric'],
            'reliabilities.*.comment'                   => ['required', 'string'],
        ];
    }

    public function ethicalRules()
    {
        return [
            'ethicals'                             => ['required', 'array'],
            'ethicals.*.id'                        => ['required', 'numeric'],
            'ethicals.*.score'                     => ['required', 'numeric'],
            'ethicals.*.explanation'               => ['required', 'string'],
        ];
    }

    public function customerServiceRules()
    {
        return [
            'customer_services'                             => ['required', 'array'],
            'customer_services.*.id'                        => ['required', 'numeric'],
            'customer_services.*.score'                     => ['required', 'numeric'],
            'customer_services.*.explanation'               => ['required', 'string'],
        ];
    }
}
