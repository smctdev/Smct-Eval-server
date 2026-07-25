<?php

namespace App\Http\Requests\create;

use Illuminate\Foundation\Http\FormRequest;

class BranchBasicAreaManager extends FormRequest
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
            $this->managerialSkillsRules(),
        );
    }

    public function mainRules()
    {
        return [
            'rating'                                => ['required', 'numeric'],
            'performanceScore'                      => ['required', 'numeric'],
            'coverageFrom'                          => ['required', 'date'],
            'coverageTo'                            => ['required', 'date'],
            'reviewTypeProbationary'                => ['nullable', 'numeric'],
            'reviewTypeRegular'                     => ['nullable', 'string'],
            'reviewTypeOthersImprovement'           => ['nullable', 'boolean'],
            'reviewTypeOthersCustom'                => ['nullable', 'string'],
            'priorityArea1'                         => ['required', 'string', 'min:20'],
            'priorityArea2'                         => ['nullable', 'string', 'min:20'],
            'priorityArea3'                         => ['nullable', 'string', 'min:20'],
            'remarks'                               => ['nullable', 'string'],
        ];
    }

    public function jobKnowledgeRules()
    {
        return [
            'jobKnowledgeScore1'                    => ['required', 'numeric'],
            'jobKnowledgeScore2'                    => ['required', 'numeric'],
            'jobKnowledgeScore3'                    => ['required', 'numeric'],
            'jobKnowledgeComments1'                 => ['required', 'string'],
            'jobKnowledgeComments2'                 => ['required', 'string'],
            'jobKnowledgeComments3'                 => ['required', 'string'],
        ];
    }

    public function qualityOfWorkRules()
    {
        return [
            'qualityOfWorkScore1'                   => ['required', 'numeric'],
            'qualityOfWorkScore2'                   => ['required', 'numeric'],
            'qualityOfWorkScore3'                   => ['required', 'numeric'],
            'qualityOfWorkScore4'                   => ['required', 'numeric'],
            'qualityOfWorkScore5'                   => ['nullable', 'numeric'],
            'qualityOfWorkScore6'                   => ['nullable', 'numeric'],
            'qualityOfWorkScore7'                   => ['nullable', 'numeric'],
            'qualityOfWorkScore8'                   => ['nullable', 'numeric'],
            'qualityOfWorkScore9'                   => ['nullable', 'numeric'],
            'qualityOfWorkScore10'                  => ['nullable', 'numeric'],
            'qualityOfWorkScore11'                  => ['nullable', 'numeric'],
            'qualityOfWorkScore12'                  => ['nullable', 'numeric'],
            'qualityOfWorkComments1'                => ['required', 'string'],
            'qualityOfWorkComments2'                => ['required', 'string'],
            'qualityOfWorkComments3'                => ['required', 'string'],
            'qualityOfWorkComments4'                => ['required', 'string'],
            'qualityOfWorkComments5'                => ['nullable', 'string'],
            'qualityOfWorkComments6'                => ['nullable', 'string'],
            'qualityOfWorkComments7'                => ['nullable', 'string'],
            'qualityOfWorkComments8'                => ['nullable', 'string'],
            'qualityOfWorkComments9'                => ['nullable', 'string'],
            'qualityOfWorkComments10'               => ['nullable', 'string'],
            'qualityOfWorkComments11'               => ['nullable', 'string'],
            'qualityOfWorkComments12'               => ['nullable', 'string'],
        ];
    }

    public function adaptabilityRules()
    {
        return [
            'adaptabilityScore1'                    => ['required', 'numeric'],
            'adaptabilityScore2'                    => ['required', 'numeric'],
            'adaptabilityScore3'                    => ['required', 'numeric'],
            'adaptabilityComments1'                 => ['required', 'string'],
            'adaptabilityComments2'                 => ['required', 'string'],
            'adaptabilityComments3'                 => ['required', 'string'],
        ];
    }

    public function teamworkRules()
    {
        return [
            'teamworkScore1'                        => ['required', 'numeric'],
            'teamworkScore2'                        => ['required', 'numeric'],
            'teamworkScore3'                        => ['required', 'numeric'],
            'teamworkComments1'                     => ['required', 'string'],
            'teamworkComments2'                     => ['required', 'string'],
            'teamworkComments3'                     => ['required', 'string'],
        ];
    }

    public function reliabilityRules()
    {
        return [
            'reliabilityScore1'                     => ['required', 'numeric'],
            'reliabilityScore2'                     => ['required', 'numeric'],
            'reliabilityScore3'                     => ['required', 'numeric'],
            'reliabilityScore4'                     => ['required', 'numeric'],
            'reliabilityComments1'                  => ['required', 'string'],
            'reliabilityComments2'                  => ['required', 'string'],
            'reliabilityComments3'                  => ['required', 'string'],
            'reliabilityComments4'                  => ['required', 'string'],
        ];
    }

    public function ethicalRules()
    {
        return [
            'ethicalScore1'                         => ['required', 'numeric'],
            'ethicalScore2'                         => ['required', 'numeric'],
            'ethicalScore3'                         => ['required', 'numeric'],
            'ethicalScore4'                         => ['required', 'numeric'],
            'ethicalExplanation1'                   => ['required', 'string'],
            'ethicalExplanation2'                   => ['required', 'string'],
            'ethicalExplanation3'                   => ['required', 'string'],
            'ethicalExplanation4'                   => ['required', 'string'],
        ];
    }

    public function managerialSkillsRules()
    {
        return [
            'managerialSkillsScore1'                 => ['required', 'numeric'],
            'managerialSkillsScore2'                 => ['required', 'numeric'],
            'managerialSkillsScore3'                 => ['required', 'numeric'],
            'managerialSkillsScore4'                 => ['required', 'numeric'],
            'managerialSkillsScore5'                 => ['required', 'numeric'],
            'managerialSkillsScore6'                 => ['required', 'numeric'],
            'managerialSkillsExplanation1'           => ['required', 'string'],
            'managerialSkillsExplanation2'           => ['required', 'string'],
            'managerialSkillsExplanation3'           => ['required', 'string'],
            'managerialSkillsExplanation4'           => ['required', 'string'],
            'managerialSkillsExplanation5'           => ['required', 'string'],
            'managerialSkillsExplanation6'           => ['required', 'string'],
        ];
    }
}
