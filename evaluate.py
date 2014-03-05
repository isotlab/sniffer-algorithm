#!/usr/bin/env python

## Open an xls based data file, and read in the values
## Call our algorith method to check if a row is indeed malicious based on the previous rows,
## and previous information the detector was given

import csv
import model

class Evaluator(object):

    def __init__(self):
        self.ACTION_INDEX = 2
        self.COMPONENT_INDEX = 4
        self.TIMESTAMP_INDEX = 6
        self.MALICIOUS_BOOL = 7

        self.count_malicious = 0
        self.count_malicious_actual = 0

        self.count_nonmalicious = 0
        self.count_nonmalicious_actual = 0

        self.count_false_negatives = 0
        self.count_false_positives = 0

        self.mailicious_actions = {}
        self.malicious_components = {}

    def log_stats (self, result, action, component, actual_class):
        if(result == True and action.strip() == 'android.provider.Telephony.SMS_SENT'):
            self.count_malicious += 1
            self.mailicious_actions[action] = self.mailicious_actions.get(action, 0) + 1
            self.malicious_components[component] = self.malicious_components.get(component, 0) + 1
        else:
            # This intent is deemed non-malicious
           self.count_nonmalicious += 1

        #print actual_class, "\n"
        if(actual_class == 'YES' and action.strip() == 'android.provider.Telephony.SMS_SENT'):
            self.count_malicious_actual += 1
            if(result != True):
                self.count_false_negatives += 1
        else:
            if(result == True):
                self.count_false_positives += 1
            self.count_nonmalicious_actual += 1


    def main (self):

        eval_model = model.Model()

        with open ('../data/Activity-Analysis-Model-Testing.csv', 'rb') as data_file:

            row_reader = csv.reader(data_file) ##, delimiter=' ', quotechar="|")
            for row in row_reader:
                self.log_stats(eval_model.process_intent(row[self.ACTION_INDEX], row[self.COMPONENT_INDEX], row[self.TIMESTAMP_INDEX]), row[self.ACTION_INDEX], row[self.COMPONENT_INDEX], row[self.MALICIOUS_BOOL])

        # Print the summary statistics
        print "SUMMARY STATISTICS: \n"

        print "# Detected Malicious Events: ", self.count_malicious
        print " Actual Malicious Events: ", self.count_malicious_actual

        print "# Detected Non-Malicious Events: ", self.count_nonmalicious
        print " Actual Non-Malicious Events: ", self.count_nonmalicious_actual

        print "# False positives: " , self.count_false_positives
        print "# False negatives: " , self.count_false_negatives

        print "% False positives: " , self.count_false_positives / (self.count_false_positives + self.count_malicious)
        print "% False negatives: " , self.count_false_negatives / (self.count_false_negatives + self.count_nonmalicious)


        print "DETAILED ACTION REPORT: \n"

        for action, count in self.mailicious_actions.items():
            print "Action: " , action, " detected with #", count, " malicious occurences"

        for component, count in self.malicious_components.items():
            print "Component: " , component, " detected with #", count, " malicious occurences"

run = Evaluator()
run.main()


