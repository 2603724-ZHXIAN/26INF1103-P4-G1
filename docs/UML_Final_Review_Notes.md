# Final UML review checkpoints

## Scope

Baseline: fetched origin/main at 0eb2784, reviewed 10 November 2026.
Diagram reviewed: exported UML_Class_Diagram.drawio.xml, page UML Class Diagram (uml1).
Review uses static source inspection. It does not certify runtime behaviour.
The shared diagram and application source have not been modified by this review.

## Checkpoint 1 completed class inventory

The source defines 24 application classes including the DataManagerError exception.
The exported diagram represents 20 of those classes.

Important missing application classes:

- BatchItem: src/batch/batch_item.py. Holds one batch item's status, content, submission and AI result.
- BatchProcessor: src/batch/batch_processor.py. Holds injected AIManager and RateLimiter collaborators and a cancellation event; provides process_batch(), _worker_task() and cancel().
- RateLimiter: src/batch/rate_limiter.py. Holds a lock, call timestamps and rate limits; provides wait_if_needed().

EngineCoordinator also has an optional _batch_processor attribute and constructor argument absent from the diagram.

DataManagerError is also absent. Its omission is not automatically a UML error: an exception class may be omitted from a deliberately scoped architectural overview. Include it if documenting error contracts and state the diagram's scope.

Already present: EmailIngestionService, EmlParser, HtmlEmailParser, IngestedEmail, BatchReport, BatchReportService, CampaignDetector and WordReportWriter. These do not need duplicate boxes.

## Confirmed method and configuration mismatches to review next

- AIManager.analyze_message() is absent from its method compartment, although the text and batch workflows use it.
- AIManager primary client may now be None; the diagram still marks exactly one primary client.
- AIManager message-analysis and prompt methods now have keyword-only include_scenarios and interaction-description arguments.
- LogicManager.evaluate_technical_threat() also accepts optional interpreted_exposure.
- VirusTotalScanner.get_report_url() takes resource_type and resource_id and may return None; the diagram shows one argument.
- Several history and retrieval methods have optional results that are still shown as mandatory results.
- _process_text_submission() now supports keyword-only email, ai_result and ai_error inputs.
- Class methods, static methods and abstract operations need an explicit consistent legend and formatting.

Some current source return annotations are inaccurate (for example, get_submission_by_id is annotated None but returns a reconstructed Submission or None). Check implementation bodies as well as annotations before copying a type into UML.

## Connector review still pending

The exported XML contains several edges with an unbound source or target. These are not automatically invalid visually, but they can detach when boxes move. Reconnect them to the intended class boundary during manual edits.
One ingestion connector has hollow diamonds at both ends; confirm the actual whole/part relationship rather than retaining a two-ended ownership marker.
Several connectors attach to a method-compartment cell rather than the class header/container. Verify the visible relationship still clearly identifies the class.
Preserve confirmed inheritance: GeminiClient/GroqClient extend BaseLLMClient; HtmlEmailParser extends the standard-library HTMLParser.
BaseLLMClient is the current application ABC/interface contract. No separate scanner interface is present in this source revision.

## Remaining stages

1. Add the missing batch-processing class boxes and coordinator field manually.
2. Correct method lists, optional results and operation notation.
3. Check ownership, collaborators, multiplicities and connector endpoints against constructors and method bodies.
4. Check layout and readable export size, save the editable diagram and exported PDF/SVG, then obtain team review.

Commit each meaningful completed stage. Keep the existing TeamAID Creation of UML diagram task In Progress until the complete revised diagram is ready for review.
